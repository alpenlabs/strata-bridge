//! Executor for the bridge proof transaction.

use std::num::NonZero;

use bitcoin::{
    Amount, FeeRate, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
};
use bitcoind_async_client::traits::Reader;
use btc_tracker::cpfp::DeadlineClass;
use operator_wallet::{FundingInput, LeaseOwner};
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use ssz::Decode;
use strata_asm_proto_bridge::OperatorClaimUnlockV1;
use strata_asm_proto_bridge_txs::BRIDGE_SUBPROTOCOL_ID;
use strata_asm_rpc::traits::{AsmMohoApiClient, AsmProofApiClient};
use strata_bridge_connectors::{Connector, prelude::ContestProofConnector};
use strata_bridge_primitives::types::{BitcoinBlockHeight, DepositIdx, OperatorIdx};
use strata_bridge_proof::{
    BridgeProofHost, BridgeProofInput, BridgeProofProgram, MerkleProofB32, MohoRecursiveOutput,
    RecursiveMohoProof,
};
use strata_bridge_proof_common::{ProofError, prove};
use strata_bridge_tx_graph::transactions::{
    bridge_proof::{BridgeProofData, BridgeProofTx},
    prelude::ContestTx,
};
use strata_identifiers::Buf32;
use tracing::{info, warn};
use zkaleido::ZkVmError;

use crate::{
    chain::{self, ConnectorFunding, CpfpKind, ParentFee, publish_signed_transaction},
    config::ExecutionConfig,
    errors::ExecutorError,
    fees::direct_funding_fee_rate,
    output_handles::OutputHandles,
};

/// Index of the general-wallet input. The connector stays at input 0, because
/// [`BridgeProofTx::signing_info_partial`] and [`BridgeProofTx::finalize_partial`] act on input 0.
const WALLET_INPUT_INDEX: usize = 1;

/// Index of the general-wallet change output, which carries the CPFP child. The proof stays at
/// output [`BridgeProofTx::PROOF_DATA_VOUT`].
const CHANGE_VOUT: u32 = 1;

/// Generates the bridge proof anchored at the given block height and publishes the bridge proof
/// transaction at the market fee.
///
/// The funded transaction is:
///
/// ```text
/// input 0: contest proof connector    output 0: zero-value OP_RETURN with the proof
/// input 1: general-wallet UTXO        output 1: general-wallet change
/// ```
///
/// The counterproof guest succeeds if output 0 is not the proof or if the operator signature is not
/// `SIGHASH_DEFAULT`, so anyone could counterprove a transaction of another shape. That signature
/// commits to the wallet input and the change, so both exist before signing.
///
/// A proof of this operator in the mempool goes back to the driver, which recovers the bump path
/// after a restart. In every other state of the connector the duty proves and publishes, as main
/// does; a connector that a block already spends then fails the publish. The duty checks the
/// connector before and after proving, because the proof takes time and a restart can race it.
///
/// The fee read and the funding run after the proof, and a failure of either publishes the proof
/// as built, so neither discards a proof.
#[expect(clippy::too_many_arguments)]
pub(super) async fn generate_and_publish_bridge_proof(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    operator_index: OperatorIdx,
    last_block_height: BitcoinBlockHeight,
    contest_txid: Txid,
    game_index: NonZero<u32>,
    contest_proof_connector: ContestProofConnector,
    operator_pubkey: XOnlyPublicKey,
) -> Result<(), ExecutorError> {
    info!(
        %deposit_idx,
        %operator_index,
        %last_block_height,
        %contest_txid,
        %game_index,
        "generating and publishing bridge proof transaction"
    );

    let connector_outpoint = OutPoint {
        txid: contest_txid,
        vout: ContestTx::PROOF_VOUT,
    };
    if let Some(own_proof) = own_proof_in_mempool(output_handles, connector_outpoint).await? {
        return drive_own_proof(output_handles, connector_outpoint, &own_proof).await;
    }

    let tap_tweak = contest_proof_connector.tweak();
    let connector_prevout = contest_proof_connector.tx_out();

    let proof_bytes = generate_bridge_proof(
        output_handles,
        deposit_idx,
        last_block_height,
        operator_pubkey,
    )
    .await?;

    if let Some(own_proof) = own_proof_in_mempool(output_handles, connector_outpoint).await? {
        return drive_own_proof(output_handles, connector_outpoint, &own_proof).await;
    }

    let data = BridgeProofData {
        contest_txid,
        proof_bytes,
        game_index,
    };
    let mut bridge_proof_tx = BridgeProofTx::new(data, contest_proof_connector);

    // A failed quote or an empty wallet must not stop the proof, which races `proof_timelock`. The
    // transaction then publishes as built: the connector pays its fee and no bump path exists.
    let funding = match direct_funding_fee_rate(&cfg.fee_source, cfg.fee_target.max_fee_rate).await
    {
        Ok(fee_rate) => synced_funding(
            output_handles,
            &bridge_proof_tx,
            connector_prevout.value,
            fee_rate,
        )
        .await
        .inspect_err(
            |e| warn!(%contest_txid, %e, "publishing the bridge proof with no wallet input"),
        )
        .ok(),
        Err(e) => {
            warn!(%contest_txid, %e, "publishing the bridge proof with no wallet input");
            None
        }
    };
    let Some(ConnectorFunding {
        input,
        lease,
        change,
        fee,
    }) = funding
    else {
        return publish_unfunded(
            output_handles,
            bridge_proof_tx,
            tap_tweak,
            operator_index,
            contest_txid,
        )
        .await;
    };
    let wallet_prevout = input.txout.clone();
    attach_wallet_funding(&mut bridge_proof_tx, &input, change);

    let signing_info = bridge_proof_tx.signing_info_partial();
    let operator_key_tweak = bridge_proof_tx.operator_key_tweak();

    let signature = output_handles
        .s2_client
        .musig2_signer()
        .sign_with_key_tweak(
            signing_info.sighash.as_ref(),
            &operator_key_tweak.to_be_bytes(),
            tap_tweak,
        )
        .await
        .map_err(|e| {
            warn!(
                %operator_index,
                %last_block_height,
                %contest_txid,
                %game_index,
                ?e,
                "failed to sign bridge proof transaction"
            );
            ExecutorError::SecretServiceErr(e)
        })?;

    let finalized_tx = bridge_proof_tx.finalize_partial(signature);
    let signed_tx = chain::sign_general_inputs(
        output_handles,
        &finalized_tx,
        &[WALLET_INPUT_INDEX],
        &[connector_prevout, wallet_prevout],
    )
    .await?;

    chain::publish_leased_transaction(
        output_handles,
        &signed_tx,
        "bridge proof",
        proof_cpfp(ParentFee::Exact(fee)),
        lease,
    )
    .await
}

/// Signs and publishes a bridge proof with no wallet input. The connector pays the fee, and the
/// transaction has no output that can carry a child.
async fn publish_unfunded(
    output_handles: &OutputHandles,
    bridge_proof_tx: BridgeProofTx,
    tap_tweak: Option<bitcoin::TapNodeHash>,
    operator_index: OperatorIdx,
    contest_txid: Txid,
) -> Result<(), ExecutorError> {
    let signing_info = bridge_proof_tx.signing_info_partial();
    let operator_key_tweak = bridge_proof_tx.operator_key_tweak();
    let signature = output_handles
        .s2_client
        .musig2_signer()
        .sign_with_key_tweak(
            signing_info.sighash.as_ref(),
            &operator_key_tweak.to_be_bytes(),
            tap_tweak,
        )
        .await
        .map_err(|e| {
            warn!(%operator_index, %contest_txid, ?e, "failed to sign bridge proof transaction");
            ExecutorError::SecretServiceErr(e)
        })?;
    let signed_tx = bridge_proof_tx.finalize_partial(signature);
    chain::publish_signed_transaction(output_handles, &signed_tx, "bridge proof", CpfpKind::None)
        .await
}

/// The CPFP path of a funded bridge proof: a child of the change output. The proof races
/// `proof_timelock`.
const fn proof_cpfp(parent_fee: ParentFee) -> CpfpKind {
    CpfpKind::PayoutCombined {
        payout_vout: CHANGE_VOUT,
        parent_fee,
        deadline: DeadlineClass::Deadline,
    }
}

/// Returns whether `mempool_spender`, a spend of the proof connector, is this operator's proof.
///
/// The proof pays change to the general wallet at [`CHANGE_VOUT`]. The other mempool spender is
/// the presigned bridge proof timeout, which carries no general change.
fn is_own_proof(mempool_spender: &bitcoin::Transaction, general_script: &ScriptBuf) -> bool {
    mempool_spender
        .output
        .get(CHANGE_VOUT as usize)
        .is_some_and(|output| output.script_pubkey == *general_script)
}

/// Returns this operator's proof when it spends the connector at `connector_outpoint` in the
/// mempool. Any other state of the connector returns `None`, and the duty builds a proof.
async fn own_proof_in_mempool(
    output_handles: &OutputHandles,
    connector_outpoint: OutPoint,
) -> Result<Option<Transaction>, ExecutorError> {
    let client = &output_handles.bitcoind_rpc_client;
    let Some(spender) = chain::mempool_spender(client, connector_outpoint).await? else {
        return Ok(None);
    };
    let spending_tx = client.get_raw_transaction_verbosity_zero(&spender).await?.0;
    Ok(is_own_proof(&spending_tx, &output_handles.general_script_pubkey).then_some(spending_tx))
}

/// Drives `own_proof`, this operator's proof in the mempool, until its burial. This recovers the
/// bump path after a restart: a rebuilt proof would take a new wallet input and a new txid.
async fn drive_own_proof(
    output_handles: &OutputHandles,
    connector_outpoint: OutPoint,
    own_proof: &Transaction,
) -> Result<(), ExecutorError> {
    info!(%connector_outpoint, txid = %own_proof.compute_txid(), "driving this operator's bridge proof from the mempool");
    publish_signed_transaction(
        output_handles,
        own_proof,
        "bridge proof",
        proof_cpfp(ParentFee::FromPrevouts),
    )
    .await
}

/// Syncs the wallet and selects the funding of `bridge_proof_tx`.
///
/// A failed sync does not stop the selection. After proving, a failed duty discards the proof, and
/// a stale view can still fund the transaction. Before proving, the same rule keeps one failed sync
/// from delaying a proof that races `proof_timelock`: the view of the last sync decides, and the
/// selection after proving can still fail.
async fn synced_funding(
    output_handles: &OutputHandles,
    bridge_proof_tx: &BridgeProofTx,
    connector_value: Amount,
    fee_rate: FeeRate,
) -> Result<ConnectorFunding, ExecutorError> {
    let mut wallet = output_handles.wallet.write().await;
    if let Err(e) = wallet.sync().await {
        warn!(?e, "could not sync wallet before funding bridge proof");
    }
    let template = funded_template(bridge_proof_tx, &wallet.general().script_pubkey());
    chain::select_connector_funding(
        &mut wallet,
        LeaseOwner::BridgeProof,
        &template,
        connector_value,
        fee_rate,
    )
}

/// Returns the funded proof with placeholder values, which gives its size. The empty wallet input
/// stays unsigned, and the connector input carries a witness of its final size.
fn funded_template(
    bridge_proof_tx: &BridgeProofTx,
    change_script: &ScriptBuf,
) -> bitcoin::Transaction {
    let placeholder = TxOut {
        value: change_script.minimal_non_dust(),
        script_pubkey: change_script.clone(),
    };
    let input = FundingInput {
        outpoint: OutPoint::null(),
        txout: placeholder.clone(),
    };
    let mut template = bridge_proof_tx.clone();
    attach_wallet_funding(&mut template, &input, placeholder);
    let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&[0; 64])
        .expect("a signature is 64 bytes");
    template.finalize_partial(signature)
}

/// Appends the general-wallet input and the change output. The order is the one that
/// [`WALLET_INPUT_INDEX`] and [`CHANGE_VOUT`] name, and this runs before the operator signs.
fn attach_wallet_funding(tx: &mut BridgeProofTx, funding: &FundingInput, change: TxOut) {
    tx.push_input(
        TxIn {
            previous_output: funding.outpoint,
            ..Default::default()
        },
        funding.txout.clone(),
    );
    tx.push_output(change);
}

/// Fetches the prover inputs anchored at the given Bitcoin block height and
/// generates the bridge proof. Returns the raw proof bytes ready to embed
/// in a bridge-proof transaction.
async fn generate_bridge_proof(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    last_block_height: BitcoinBlockHeight,
    operator_pubkey: XOnlyPublicKey,
) -> Result<Vec<u8>, ExecutorError> {
    let proof_input = fetch_bridge_proof_input(
        output_handles,
        deposit_idx,
        last_block_height,
        operator_pubkey,
    )
    .await?;

    info!(%last_block_height, "generating bridge proof");
    let prove_start = std::time::Instant::now();
    let receipt = match output_handles.bridge_proof_host.clone() {
        BridgeProofHost::Native(host) => prove::<BridgeProofProgram, _>(proof_input, host).await?,
        #[cfg(feature = "sp1")]
        BridgeProofHost::Sp1(host) => prove::<BridgeProofProgram, _>(proof_input, *host).await?,
    };
    info!(
        %last_block_height,
        elapsed = ?prove_start.elapsed(),
        "bridge proof generated",
    );

    let payload = borsh::to_vec(&receipt)
        .map_err(|e| ProofError::ZkVm(ZkVmError::Other(format!("encode proof receipt: {e}"))))?;
    Ok(payload)
}

/// Fetches the ASM RPC inputs anchored at the given Bitcoin block height and
/// assembles them into a [`BridgeProofInput`] ready to feed into the bridge
/// proof program.
async fn fetch_bridge_proof_input(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    last_block_height: BitcoinBlockHeight,
    operator_pubkey: XOnlyPublicKey,
) -> Result<BridgeProofInput, ExecutorError> {
    info!(%last_block_height, "fetching bridge proof inputs");
    let fetch_start = std::time::Instant::now();

    let recent_block_hash = output_handles
        .bitcoind_rpc_client
        .get_block_hash(last_block_height)
        .await?;
    info!(
        %last_block_height,
        %recent_block_hash,
        "resolved last-seen block hash for bridge proof anchor"
    );

    let claim_unlock = OperatorClaimUnlockV1::new(deposit_idx, Buf32(operator_pubkey.serialize()));
    let leaf_hash = claim_unlock.compute_hash();

    let asm = &output_handles.asm_rpc_client;
    let moho_state = asm
        .get_moho_state(recent_block_hash)
        .await
        .map_err(|e| ExecutorError::AsmRpcErr(format!("get_moho_state: {e}")))?
        .ok_or_else(|| {
            ExecutorError::AsmRpcErr(format!("moho state unavailable at {recent_block_hash}"))
        })?;
    let raw_moho_proof = asm
        .get_moho_proof(recent_block_hash)
        .await
        .map_err(|e| ExecutorError::AsmRpcErr(format!("get_moho_proof: {e}")))?
        .ok_or_else(|| {
            ExecutorError::AsmRpcErr(format!("moho proof unavailable at {recent_block_hash}"))
        })?;
    let mmr_proof_bytes = asm
        .get_export_entry_mmr_proof(recent_block_hash, BRIDGE_SUBPROTOCOL_ID, leaf_hash)
        .await
        .map_err(|e| {
            ExecutorError::AsmRpcErr(format!(
                "get_export_entry_mmr_proof for leaf {leaf_hash:?} at {recent_block_hash}: {e}"
            ))
        })?;
    info!(
        mmr_proof_len = mmr_proof_bytes.len(),
        "fetched ASM proof inputs for bridge proof"
    );

    let mmr_proof = MerkleProofB32::from_ssz_bytes(&mmr_proof_bytes)
        .map_err(|e| ExecutorError::AsmRpcErr(format!("decode mmr_proof ssz: {e:?}")))?;

    let receipt = raw_moho_proof.0.receipt();
    let moho_output = MohoRecursiveOutput::from_ssz_bytes(receipt.public_values().as_bytes())
        .map_err(|e| {
            ExecutorError::AsmRpcErr(format!("decode moho recursive output ssz: {e:?}"))
        })?;
    let moho_proof = RecursiveMohoProof::new(
        moho_output.attestation().clone(),
        receipt.proof().as_bytes().to_vec(),
    );

    let proof_input = BridgeProofInput {
        moho_state,
        moho_proof,
        claim_unlock,
        claim_unlock_inclusion_proof: mmr_proof,
    };
    info!(
        %last_block_height,
        %recent_block_hash,
        elapsed = ?fetch_start.elapsed(),
        "bridge proof inputs prepared",
    );

    Ok(proof_input)
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Network, TapSighashType, Weight,
        hashes::Hash,
        relative,
        secp256k1::SECP256K1,
        sighash::{Prevouts, SighashCache},
        transaction::InputWeightPrediction,
    };

    use super::*;

    fn key(seed: u8) -> XOnlyPublicKey {
        bitcoin::secp256k1::Keypair::from_seckey_slice(SECP256K1, &[seed; 32])
            .expect("valid secret key")
            .x_only_public_key()
            .0
    }

    const GAME_INDEX: NonZero<u32> = NonZero::new(4).unwrap();

    fn connector() -> ContestProofConnector {
        ContestProofConnector::new(
            Network::Regtest,
            key(1),
            key(2),
            GAME_INDEX,
            relative::Height::from_height(10),
            Amount::from_sat(374),
        )
    }

    fn proof_tx() -> BridgeProofTx {
        let data = BridgeProofData {
            contest_txid: Txid::all_zeros(),
            proof_bytes: vec![0xab; 400],
            game_index: GAME_INDEX,
        };
        BridgeProofTx::new(data, connector())
    }

    fn wallet_script() -> ScriptBuf {
        bitcoin::Address::p2tr(SECP256K1, key(3), None, Network::Regtest).script_pubkey()
    }

    fn funding() -> FundingInput {
        FundingInput {
            outpoint: OutPoint::new(Txid::from_byte_array([6; 32]), 1),
            txout: TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: wallet_script(),
            },
        }
    }

    fn change(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: wallet_script(),
        }
    }

    /// The counterproof guest parses output 0 and the signature on the connector input.
    #[test]
    fn a_wallet_built_proof_keeps_the_op_return_at_output_zero() {
        let mut tx = proof_tx();
        let contest_outpoint = tx.as_ref().input[0].previous_output;
        let proof_output = tx.as_ref().output[0].clone();

        attach_wallet_funding(&mut tx, &funding(), change(45_000));
        let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&[1; 64]).unwrap();
        let signed = tx.finalize_partial(signature);

        assert_eq!(signed.input.len(), 2);
        assert_eq!(signed.input[0].previous_output, contest_outpoint);
        assert_eq!(
            signed.input[WALLET_INPUT_INDEX].previous_output,
            funding().outpoint
        );
        assert!(
            signed.input[WALLET_INPUT_INDEX].witness.is_empty(),
            "the wallet input is signed after finalize_partial"
        );
        assert_eq!(signed.output.len(), 2);
        assert_eq!(
            signed.output[BridgeProofTx::PROOF_DATA_VOUT as usize],
            proof_output
        );
        assert!(proof_output.script_pubkey.is_op_return());
        assert_eq!(signed.output[CHANGE_VOUT as usize], change(45_000));
    }

    /// The guest succeeds on any sighash type but the default, so the operator signs the default
    /// sighash over both prevouts of the funded transaction.
    #[test]
    fn the_operator_signs_the_default_sighash_of_the_funded_tx() {
        let mut tx = proof_tx();
        attach_wallet_funding(&mut tx, &funding(), change(45_000));

        let prevouts = [connector().tx_out(), funding().txout];
        let expected = SighashCache::new(tx.as_ref())
            .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), TapSighashType::Default)
            .expect("valid sighash");

        assert_eq!(
            tx.signing_info_partial().sighash,
            bitcoin::secp256k1::Message::from(expected)
        );
    }

    #[test]
    fn the_planned_fee_pays_the_rate_on_the_signed_size() {
        let tx = proof_tx();
        let rate = FeeRate::from_sat_per_vb(40).expect("valid rate");
        let script = wallet_script();
        let prediction = InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH;

        let fee = chain::funded_tx_fee(&funded_template(&tx, &script), prediction, rate)
            .expect("no overflow");

        let mut funded = tx;
        attach_wallet_funding(&mut funded, &funding(), change(10_000));
        let signature = bitcoin::secp256k1::schnorr::Signature::from_slice(&[1; 64]).unwrap();
        let mut signed = funded.finalize_partial(signature);
        signed.input[WALLET_INPUT_INDEX].witness.push([2; 64]);

        assert!(fee >= rate.fee_wu(signed.weight()).expect("no overflow"));
        assert!(
            fee <= rate
                .fee_wu(signed.weight() + Weight::from_wu(5))
                .expect("no overflow")
        );
    }

    fn spender(outputs: Vec<TxOut>) -> bitcoin::Transaction {
        bitcoin::Transaction {
            version: bitcoin::transaction::Version(3),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![],
            output: outputs,
        }
    }

    #[test]
    fn only_a_spender_with_general_change_is_this_operators_proof() {
        let general = wallet_script();
        let op_return = TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return([1]),
        };
        let own_proof = spender(vec![op_return, change(1_000)]);
        let timeout = spender(vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: bitcoin::Address::p2tr(SECP256K1, key(4), None, Network::Regtest)
                .script_pubkey(),
        }]);

        assert!(is_own_proof(&own_proof, &general));
        assert!(
            !is_own_proof(&timeout, &general),
            "the bridge proof timeout has one output and carries no general change"
        );
    }
}
