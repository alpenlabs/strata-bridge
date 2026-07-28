//! Executor for the counterproof transaction.

use std::num::NonZero;

use bitcoin::{Amount, Network, ScriptBuf, Transaction, XOnlyPublicKey, consensus, relative};
use bitcoind_async_client::{error::ClientError, traits::Reader};
use btc_tracker::event::TxStatus;
use metrics::counter;
use musig2::secp256k1::schnorr::Signature;
use ssz::Decode;
use strata_asm_proto_bridge_v1::OperatorClaimUnlock;
use strata_asm_proto_bridge_v1_txs::BRIDGE_V1_SUBPROTOCOL_ID;
use strata_asm_rpc::traits::AsmProofApiClient;
use strata_bridge_connectors::prelude::{ContestCounterproofWitness, ContestProofConnector};
use strata_bridge_counterproof::{
    BitcoinTxOut, BridgeCounterproofHost, CounterproofInput, CounterproofMode, CounterproofProgram,
    HeavierChainProof, RawBitcoinTx,
};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    proof::verify_bridge_proof,
    types::{DepositIdx, OperatorIdx},
};
use strata_bridge_proof::{
    BridgeProofOutput, MerkleProofB32, MohoRecursiveOutput, MohoState, RecursiveMohoProof,
};
use strata_bridge_proof_common::prove;
use strata_bridge_tx_graph::transactions::counterproof::CounterproofTx;
use strata_crypto::hash;
use strata_mosaic_client_api::types::{G16ProofRaw, N_WITHDRAWAL_INPUT_WIRES, Role};
use tracing::{info, warn};
use zkaleido::ProofReceipt;
#[cfg(feature = "sp1")]
use zkaleido_sp1_groth16_verifier::Sp1Groth16Proof;

use crate::{
    chain::publish_signed_transaction, config::ExecutionConfig, errors::ExecutorError,
    output_handles::OutputHandles,
};

/// Handles a [`GraphDuty::PotentialCounterProof`]: verifies the observed bridge proof and publishes
/// a counterproof if there are grounds to challenge it, either because the proof is invalid or
/// because our heavier canonical chain contradicts its claim.
#[expect(clippy::too_many_arguments)]
pub(super) async fn evaluate_and_publish_counterproof(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    counterproof_tx: CounterproofTx,
    operator_idx: OperatorIdx,
    deposit_idx: DepositIdx,
    game_index: NonZero<u32>,
    n_of_n_signature: Signature,
    proof: ProofReceipt,
    bridge_proof_tx: Transaction,
    operator_table: &OperatorTable,
) -> Result<(), ExecutorError> {
    info!(%deposit_idx, %operator_idx, %game_index, "evaluating potential counterproof for graph");

    let mode = if verify_bridge_proof(&cfg.graph_sm_cfg.bridge_proof_predicate, &proof) {
        let Some(heavier_chain_proof) =
            detect_heavier_chain(output_handles, deposit_idx, operator_idx, &proof).await?
        else {
            info!(
                %deposit_idx,
                %operator_idx,
                %game_index,
                "proof valid and no heavier contradicting chain; skipping counterproof",
            );
            return Ok(());
        };
        info!(%deposit_idx, %operator_idx, %game_index, "heavier contradicting chain detected; publishing counterproof");
        CounterproofMode::HeavierChain(heavier_chain_proof)
    } else {
        // Invalid proof: challenge it outright.
        info!(%deposit_idx, %operator_idx, %game_index, "bridge proof failed verification; publishing counterproof");
        CounterproofMode::InvalidBridgeProof
    };

    generate_and_publish_counterproof(
        cfg,
        output_handles,
        counterproof_tx,
        operator_idx,
        deposit_idx,
        game_index,
        n_of_n_signature,
        bridge_proof_tx,
        operator_table,
        mode,
    )
    .await
}

/// Generates the counterproof or reuses already-completed adaptor signatures, assembles the
/// witness with the pre-computed N-of-N signature, and publishes the counterproof transaction to
/// Bitcoin.
#[expect(clippy::too_many_arguments)]
async fn generate_and_publish_counterproof(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    counterproof_tx: CounterproofTx,
    operator_idx: OperatorIdx,
    deposit_idx: DepositIdx,
    game_index: NonZero<u32>,
    n_of_n_signature: Signature,
    bridge_proof_tx: Transaction,
    operator_table: &OperatorTable,
    mode: CounterproofMode,
) -> Result<(), ExecutorError> {
    info!(%deposit_idx, %operator_idx, %game_index, "generating and publishing counterproof for graph");

    let completed_sigs = if let Some(completed_sigs) = output_handles
        .mosaic_client
        .get_completed_adaptor_sigs(operator_idx, game_index.into())
        .await
        .map_err(|e| {
            warn!(%deposit_idx, %game_index, %operator_idx, ?e, "failed to get completed adaptor sigs for counterproof");
            ExecutorError::MosaicErr(format!("get_completed_adaptor_sigs: {e:?}"))
        })?
    {
        info!(
            %deposit_idx,
            %game_index,
            %operator_idx,
            "reusing completed adaptor signatures for counterproof",
        );
        completed_sigs
    } else {
        let setup_available = output_handles
            .mosaic_client
            .is_setup_available(operator_idx, Role::Garbler, game_index.into())
            .await
            .map_err(|e| {
                warn!(%deposit_idx, %game_index, %operator_idx, ?e, "failed to check mosaic setup availability");
                ExecutorError::MosaicErr(format!("is_setup_available: {e:?}"))
            })?;

        if !setup_available {
            warn!(
                %deposit_idx,
                %game_index,
                %operator_idx,
                "skipping counterproof generation because mosaic setup is unavailable",
            );
            return Ok(());
        }

        let counterproof_data = generate_counterproof(
            cfg,
            output_handles,
            deposit_idx,
            operator_idx,
            game_index,
            bridge_proof_tx,
            operator_table,
            mode,
        )
        .await?;

        // Complete adaptor signatures via mosaic (we are the garbler/watchtower).
        info!(%deposit_idx, %game_index, %operator_idx, "completing adaptor signatures via mosaic for graph");
        output_handles
            .mosaic_client
            .complete_adaptor_sigs(operator_idx, game_index.into(), counterproof_data)
            .await
            .map_err(|e| {
                warn!(%deposit_idx, %game_index, %operator_idx, ?e, "failed to complete adaptor sigs for counterproof");
                ExecutorError::MosaicErr(format!("complete_adaptor_sigs: {e:?}"))
            })?
    };

    // The counterproof leaf script expects one operator signature per byte of counterproof
    // data (n_data = N_DEPOSIT + N_WITHDRAWAL wires), so we need ALL completed adaptor sigs.
    let operator_signatures = completed_sigs.to_vec();

    info!(%deposit_idx, %game_index, %operator_idx, "signing and publishing counterproof tx for graph");

    let witness = ContestCounterproofWitness {
        n_of_n_signature,
        operator_signatures,
    };
    let signed_tx = counterproof_tx.finalize(&witness);

    publish_signed_transaction(
        &output_handles.tx_driver,
        &signed_tx,
        "counterproof",
        TxStatus::is_buried,
    )
    .await
}

/// Prepares the prover inputs and generates the counterproof, returning the
/// [`G16ProofRaw`].
///
/// Under the SP1 host, the receipt's SP1-wrapped Groth16 proof is unwrapped
/// and gnark-compressed into a [`G16ProofRaw`]. Under the native host a zero-filled [`G16ProofRaw`]
/// is returned as a stand-in.
#[expect(clippy::too_many_arguments)]
async fn generate_counterproof(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    operator_idx: OperatorIdx,
    game_index: NonZero<u32>,
    bridge_proof_tx: Transaction,
    operator_table: &OperatorTable,
    mode: CounterproofMode,
) -> Result<G16ProofRaw, ExecutorError> {
    counter!("strata_bridge_counterproof_generation_attempts").increment(1);

    let proof_input = fetch_counterproof_input(
        cfg,
        output_handles,
        deposit_idx,
        operator_idx,
        game_index,
        bridge_proof_tx,
        operator_table,
        mode,
    )
    .await?;

    info!(%deposit_idx, %game_index, %operator_idx, "generating counterproof for graph");
    let prove_start = std::time::Instant::now();
    let counterproof_data = match output_handles.counterproof_host.clone() {
        BridgeCounterproofHost::Native(host) => {
            let _receipt = prove::<CounterproofProgram, _>(proof_input, host).await?;
            G16ProofRaw([0u8; N_WITHDRAWAL_INPUT_WIRES])
        }
        #[cfg(feature = "sp1")]
        BridgeCounterproofHost::Sp1(host) => {
            let receipt = prove::<CounterproofProgram, _>(proof_input, *host).await?;
            let parsed = Sp1Groth16Proof::parse(receipt.proof().as_bytes())
                .expect("SP1 host must produce a parseable Groth16 proof");
            G16ProofRaw(parsed.proof.to_gnark_compressed_bytes())
        }
    };
    info!(
        %deposit_idx,
        %game_index,
        %operator_idx,
        elapsed = ?prove_start.elapsed(),
        "counterproof generated for graph",
    );

    Ok(counterproof_data)
}

/// Fetches the inputs needed for counterproof generation and assembles them
/// into a [`CounterproofInput`] ready to feed into the counterproof program.
#[expect(clippy::too_many_arguments)]
async fn fetch_counterproof_input(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    operator_idx: OperatorIdx,
    game_index: NonZero<u32>,
    bridge_proof_tx: Transaction,
    operator_table: &OperatorTable,
    mode: CounterproofMode,
) -> Result<CounterproofInput, ExecutorError> {
    info!(%deposit_idx, %operator_idx, %game_index, "fetching counterproof inputs for graph");

    let (operator_xonly, n_of_n_xonly) = counterproof_operator_keys(operator_table, operator_idx);

    let proof_timelock = cfg.graph_sm_cfg.game_graph_params.proof_timelock.value();

    let mut bridge_proof_tx_prevouts = Vec::with_capacity(bridge_proof_tx.input.len());
    for txin in &bridge_proof_tx.input {
        let outpoint = txin.previous_output;
        let parent_tx = output_handles
            .bitcoind_rpc_client
            .get_raw_transaction_verbosity_zero(&outpoint.txid)
            .await?
            .0;
        let prevout = parent_tx
            .output
            .get(outpoint.vout as usize)
            .cloned()
            .ok_or_else(|| {
                ExecutorError::BitcoinRpcErr(ClientError::MalformedResponse(format!(
                    "prevout vout {} out of bounds for parent tx {}",
                    outpoint.vout, outpoint.txid,
                )))
            })?;
        let prevout = BitcoinTxOut::try_from(prevout).map_err(|e| {
            ExecutorError::InvalidTxStructure(format!(
                "prevout vout {} of parent tx {} is not a valid BitcoinTxOut: {e}",
                outpoint.vout, outpoint.txid,
            ))
        })?;
        bridge_proof_tx_prevouts.push(prevout);
    }

    let expected_spk = ScriptBuf::new_p2tr_tweaked(
        ContestProofConnector::new(
            Network::Bitcoin,
            n_of_n_xonly,
            operator_xonly,
            game_index,
            relative::Height::from_height(proof_timelock),
            Amount::ZERO,
        )
        .output_key(),
    );

    let bridge_proof_tx_input_idx = bridge_proof_tx_prevouts
        .iter()
        .position(|prevout| prevout.inner().script_pubkey == expected_spk)
        .ok_or_else(|| {
            ExecutorError::InvalidTxStructure(
                "bridge proof tx does not spend the ContestProofConnector".to_string(),
            )
        })? as u32;

    Ok(CounterproofInput {
        game_idx: game_index.get(),
        operator_pubkey: operator_xonly.into(),
        n_of_n_pubkey: n_of_n_xonly.into(),
        proof_timelock,
        bridge_proof_tx: RawBitcoinTx::from_raw_bytes(consensus::serialize(&bridge_proof_tx)),
        bridge_proof_tx_prevouts,
        bridge_proof_tx_input_idx,
        mode,
    })
}

/// Checks whether our canonical ASM view is a strictly heavier chain that contradicts the
/// operator's bridge proof, returning the [`HeavierChainProof`] witness to counter with, or
/// `None` when there is nothing to challenge.
async fn detect_heavier_chain(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    operator_idx: OperatorIdx,
    proof: &ProofReceipt,
) -> Result<Option<HeavierChainProof>, ExecutorError> {
    let operator_commitment = BridgeProofOutput::from_ssz_bytes(proof.public_values().as_bytes())
        .map_err(|e| {
        ExecutorError::InvalidTxStructure(format!("decode bridge proof output ssz: {e:?}"))
    })?;

    let (tip_hash, moho_state) = fetch_canonical_moho_state(output_handles).await?;

    let container = moho_state
        .export_state()
        .containers()
        .iter()
        .find(|c| c.container_id() == BRIDGE_V1_SUBPROTOCOL_ID)
        .ok_or_else(|| {
            ExecutorError::AsmRpcErr("moho state missing bridge-v1 export container".to_string())
        })?;

    // The operator's claim is consistent with our view; nothing to challenge.
    if is_claim_in_canonical_chain(output_handles, tip_hash, &operator_commitment).await? {
        return Ok(None);
    }

    let is_heavier = gt_little_endian(container.extra_data(), &operator_commitment.total_pow);
    if !is_heavier {
        warn!(
            %deposit_idx,
            %operator_idx,
            "operator claim unlock not in our chain but our chain is not heavier; cannot challenge",
        );
        return Ok(None);
    }

    let moho_proof = fetch_moho_proof(output_handles, tip_hash).await?;
    Ok(Some(HeavierChainProof::new(
        moho_state,
        moho_proof,
        OperatorClaimUnlock::new(deposit_idx, operator_idx),
        MerkleProofB32::new_zero(),
    )))
}

/// Resolves our current Bitcoin tip and fetches the decoded [`MohoState`] the ASM derived at it.
async fn fetch_canonical_moho_state(
    output_handles: &OutputHandles,
) -> Result<(bitcoin::BlockHash, MohoState), ExecutorError> {
    let tip_height = output_handles.bitcoind_rpc_client.get_block_count().await?;
    let tip_hash = output_handles
        .bitcoind_rpc_client
        .get_block_hash(tip_height)
        .await?;

    let moho_state_bytes = output_handles
        .asm_rpc_client
        .get_moho_state(tip_hash)
        .await
        .map_err(|e| ExecutorError::AsmRpcErr(format!("get_moho_state: {e}")))?
        .ok_or_else(|| ExecutorError::AsmRpcErr(format!("moho state unavailable at {tip_hash}")))?;
    let moho_state = MohoState::from_ssz_bytes(&moho_state_bytes)
        .map_err(|e| ExecutorError::AsmRpcErr(format!("decode moho_state ssz: {e:?}")))?;

    Ok((tip_hash, moho_state))
}

/// Checks whether the operator's committed claim unlock is included in our canonical chain at
/// the committed MMR index, i.e. the operator's claim is consistent with our view.
async fn is_claim_in_canonical_chain(
    output_handles: &OutputHandles,
    tip_hash: bitcoin::BlockHash,
    operator_commitment: &BridgeProofOutput,
) -> Result<bool, ExecutorError> {
    let claim_leaf = hash::raw(&operator_commitment.claim_unlock).0;
    // `None` means the leaf is not in our chain at all.
    let Some(inclusion_bytes) = output_handles
        .asm_rpc_client
        .get_export_entry_mmr_proof(tip_hash, BRIDGE_V1_SUBPROTOCOL_ID, claim_leaf.to_vec())
        .await
        .map_err(|e| ExecutorError::AsmRpcErr(format!("get_export_entry_mmr_proof: {e}")))?
    else {
        return Ok(false);
    };

    let inclusion_proof = MerkleProofB32::from_ssz_bytes(&inclusion_bytes)
        .map_err(|e| ExecutorError::AsmRpcErr(format!("decode mmr proof ssz: {e:?}")))?;
    Ok(inclusion_proof.index() == operator_commitment.mmr_idx)
}

/// Fetches the recursive Moho proof for `block_hash` from the ASM and rebuilds the
/// [`RecursiveMohoProof`] the same way the bridge proof assembles its input.
async fn fetch_moho_proof(
    output_handles: &OutputHandles,
    block_hash: bitcoin::BlockHash,
) -> Result<RecursiveMohoProof, ExecutorError> {
    let raw_moho_proof = output_handles
        .asm_rpc_client
        .get_moho_proof(block_hash)
        .await
        .map_err(|e| ExecutorError::AsmRpcErr(format!("get_moho_proof: {e}")))?
        .ok_or_else(|| {
            ExecutorError::AsmRpcErr(format!("moho proof unavailable at {block_hash}"))
        })?;
    let receipt = raw_moho_proof.0.receipt();
    let moho_output = MohoRecursiveOutput::from_ssz_bytes(receipt.public_values().as_bytes())
        .map_err(|e| {
            ExecutorError::AsmRpcErr(format!("decode moho recursive output ssz: {e:?}"))
        })?;
    Ok(RecursiveMohoProof::new(
        moho_output.attestation().clone(),
        receipt.proof().as_bytes().to_vec(),
    ))
}

/// Returns `true` if `lhs > rhs` for 32-byte little-endian integers (accumulated Bitcoin PoW).
fn gt_little_endian(lhs: &[u8; 32], rhs: &[u8; 32]) -> bool {
    lhs.iter().rev().cmp(rhs.iter().rev()).is_gt()
}

fn counterproof_operator_keys(
    operator_table: &OperatorTable,
    operator_idx: OperatorIdx,
) -> (XOnlyPublicKey, XOnlyPublicKey) {
    let operator_xonly = operator_table
        .idx_to_btc_key(&operator_idx)
        .expect("operator_idx must be present in the operator table")
        .x_only_public_key()
        .0;

    let n_of_n_xonly = operator_table.aggregated_btc_key().x_only_public_key().0;

    (operator_xonly, n_of_n_xonly)
}

#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::bridge_fixtures::test_operator_table;

    use super::{counterproof_operator_keys, gt_little_endian};

    #[test]
    fn gt_little_endian_compares_pow_as_little_endian_integers() {
        let zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[0] = 1; // little-endian 1

        let mut big = [0u8; 32];
        big[31] = 1; // little-endian 2^248, far larger than `one`

        assert!(gt_little_endian(&one, &zero), "1 > 0");
        assert!(!gt_little_endian(&zero, &one), "0 is not > 1");
        assert!(
            !gt_little_endian(&one, &one),
            "equal is not strictly greater"
        );
        assert!(gt_little_endian(&big, &one), "high-order byte dominates");
        assert!(
            !gt_little_endian(&one, &big),
            "low-order byte does not dominate"
        );
    }

    #[test]
    fn counterproof_keys_use_supplied_operator_table_snapshot() {
        let historical_table = test_operator_table(3, 0);
        let later_table = test_operator_table(4, 0);

        let (historical_operator_key, historical_aggregate_key) =
            counterproof_operator_keys(&historical_table, 1);
        let (later_operator_key, later_aggregate_key) = counterproof_operator_keys(&later_table, 1);

        assert_eq!(
            historical_operator_key, later_operator_key,
            "same operator index should resolve to the same operator key"
        );
        assert_ne!(
            historical_aggregate_key, later_aggregate_key,
            "aggregate key must come from the supplied table snapshot"
        );
    }
}
