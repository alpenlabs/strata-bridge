//! Executor for the bridge proof transaction.

use std::num::NonZero;

use bitcoind_async_client::traits::Reader;
use btc_tracker::event::TxStatus;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use ssz::Decode;
use strata_asm_proto_bridge_v1::OperatorClaimUnlock;
use strata_asm_proto_bridge_v1_txs::BRIDGE_V1_SUBPROTOCOL_ID;
use strata_asm_rpc::traits::AsmProofApiClient;
use strata_bridge_connectors::{Connector, prelude::ContestProofConnector};
use strata_bridge_primitives::types::{BitcoinBlockHeight, DepositIdx, OperatorIdx};
use strata_bridge_proof::{
    BridgeProofHost, BridgeProofInput, BridgeProofProgram, MerkleProofB32, MohoRecursiveOutput,
    MohoState, RecursiveMohoProof,
};
use strata_bridge_proof_common::{ProofError, prove};
use strata_bridge_tx_graph::transactions::bridge_proof::{BridgeProofData, BridgeProofTx};
use strata_codec::encode_to_vec;
use strata_crypto::hash;
use tracing::{info, warn};
use zkaleido::ZkVmError;

use crate::{
    chain::{self, CpfpKind, publish_signed_transaction},
    errors::ExecutorError,
    output_handles::OutputHandles,
};

/// Generates the bridge proof anchored at the given block height and publishes
/// the resulting bridge proof transaction.
pub(super) async fn generate_and_publish_bridge_proof(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    operator_index: OperatorIdx,
    last_block_height: BitcoinBlockHeight,
    contest_txid: bitcoin::Txid,
    game_index: NonZero<u32>,
    contest_proof_connector: ContestProofConnector,
) -> Result<(), ExecutorError> {
    info!(
        %deposit_idx,
        %operator_index,
        %last_block_height,
        %contest_txid,
        %game_index,
        "generating and publishing bridge proof transaction"
    );

    let proof_bytes = generate_bridge_proof(
        output_handles,
        deposit_idx,
        operator_index,
        last_block_height,
    )
    .await?;

    let data = BridgeProofData {
        contest_txid,
        proof_bytes,
        game_index,
    };

    let tap_tweak = contest_proof_connector.tweak();
    let bridge_proof_tx = BridgeProofTx::new(data, contest_proof_connector);
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

    let signed_tx = bridge_proof_tx.finalize_partial(signature);

    // Bridge proof tx has no operator-owned output and no keyed anchor — its only output is
    // a zero-value OP_RETURN encoding the proof bytes. The fee comes from the contest
    // proof-connector input's surcharge. Not CPFP-able from the operator side; eviction
    // resubmit is the only recovery path.
    publish_signed_transaction(
        output_handles,
        &signed_tx,
        "bridge proof",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(&signed_tx),
        CpfpKind::None,
    )
    .await
}

/// Fetches the prover inputs anchored at the given Bitcoin block height and
/// generates the bridge proof. Returns the raw proof bytes ready to embed
/// in a bridge-proof transaction.
async fn generate_bridge_proof(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    operator_index: OperatorIdx,
    last_block_height: BitcoinBlockHeight,
) -> Result<Vec<u8>, ExecutorError> {
    let proof_input = fetch_bridge_proof_input(
        output_handles,
        deposit_idx,
        operator_index,
        last_block_height,
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
    operator_index: OperatorIdx,
    last_block_height: BitcoinBlockHeight,
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

    let operator_claim_unlock = OperatorClaimUnlock::new(deposit_idx, operator_index);
    let claim_unlock = encode_to_vec(&operator_claim_unlock)
        .map_err(|e| ExecutorError::AsmRpcErr(format!("encode claim_unlock: {e}")))?;
    let leaf_hash = hash::raw(&claim_unlock).0;

    let asm = &output_handles.asm_rpc_client;
    let moho_state_bytes = asm
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
        .get_export_entry_mmr_proof(
            recent_block_hash,
            BRIDGE_V1_SUBPROTOCOL_ID,
            leaf_hash.to_vec(),
        )
        .await
        .map_err(|e| ExecutorError::AsmRpcErr(format!("get_export_entry_mmr_proof: {e}")))?
        .ok_or_else(|| {
            ExecutorError::AsmRpcErr(format!(
                "mmr proof unavailable for leaf {leaf_hash:?} at {recent_block_hash}"
            ))
        })?;
    info!(
        moho_state_len = moho_state_bytes.len(),
        mmr_proof_len = mmr_proof_bytes.len(),
        "fetched ASM proof inputs for bridge proof"
    );

    let moho_state = MohoState::from_ssz_bytes(&moho_state_bytes)
        .map_err(|e| ExecutorError::AsmRpcErr(format!("decode moho_state ssz: {e:?}")))?;
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
