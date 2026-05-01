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
use strata_bridge_proof::{BridgeProofInput, BridgeProofProgram, MerkleProofB32, MohoState};
use strata_bridge_proofs_common::prove;
use strata_bridge_tx_graph::transactions::bridge_proof::{BridgeProofData, BridgeProofTx};
use strata_codec::encode_to_vec;
use tracing::{info, warn};

use crate::{
    chain::publish_signed_transaction, errors::ExecutorError, output_handles::OutputHandles,
};

/// Generates and publishes the bridge proof transaction.
///
/// Runs [`generate_bridge_proof`] to obtain the proof bytes, then assembles
/// the bridge-proof transaction, signs it via the secret service, and
/// broadcasts it through the tx driver.
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
                %contest_txid,
                %game_index,
                ?e,
                "failed to sign bridge proof transaction"
            );
            ExecutorError::SecretServiceErr(e)
        })?;

    let signed_tx = bridge_proof_tx.finalize_partial(signature);

    publish_signed_transaction(
        &output_handles.tx_driver,
        &signed_tx,
        "bridge proof",
        TxStatus::is_buried,
    )
    .await
}

/// Fetches ASM proof inputs anchored at the most recent Bitcoin block and
/// runs the bridge proof program. Returns the encoded proof bytes ready to
/// embed in a bridge-proof transaction.
/// follow-up under <https://alpenlabs.atlassian.net/browse/STR-1977>.
async fn generate_bridge_proof(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    operator_index: OperatorIdx,
    last_block_height: BitcoinBlockHeight,
) -> Result<Vec<u8>, ExecutorError> {
    let recent_block_hash = output_handles
        .bitcoind_rpc_client
        .get_block_hash(last_block_height)
        .await?;
    info!(
        %last_block_height,
        %recent_block_hash,
        "resolved last-seen block hash for bridge proof anchor"
    );

    // The ASM bridge-v1 subprotocol records each fulfilled withdrawal as an
    // `OperatorClaimUnlock` leaf in its export entries MMR; we re-derive the leaf here
    // and ask the ASM for the matching MMR inclusion proof anchored at the same block.
    let operator_claim_unlock = OperatorClaimUnlock::new(deposit_idx, operator_index);
    let leaf_hash = operator_claim_unlock.compute_hash();

    let moho_state = output_handles
        .asm_rpc_client
        .get_moho_state(recent_block_hash)
        .await
        .map_err(|e| ExecutorError::AsmRpcErr(format!("get_moho_state: {e}")))?
        .ok_or_else(|| {
            ExecutorError::AsmRpcErr(format!("moho state unavailable at {recent_block_hash}"))
        })?;
    let moho_proof = output_handles
        .asm_rpc_client
        .get_moho_proof(recent_block_hash)
        .await
        .map_err(|e| ExecutorError::AsmRpcErr(format!("get_moho_proof: {e}")))?
        .ok_or_else(|| {
            ExecutorError::AsmRpcErr(format!("moho proof unavailable at {recent_block_hash}"))
        })?;
    let mmr_proof = output_handles
        .asm_rpc_client
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
        moho_state_len = moho_state.len(),
        mmr_proof_len = mmr_proof.len(),
        ?mmr_proof,
        "fetched ASM proof inputs for bridge proof"
    );

    // Decode SSZ-shaped fields; foreign-encoded ones (Groth16, Codec) pass through as bytes.
    let moho_state = MohoState::from_ssz_bytes(&moho_state)
        .map_err(|e| ExecutorError::AsmRpcErr(format!("decode moho_state ssz: {e:?}")))?;
    let mmr_proof = MerkleProofB32::from_ssz_bytes(&mmr_proof)
        .map_err(|e| ExecutorError::AsmRpcErr(format!("decode mmr_proof ssz: {e:?}")))?;

    let moho_proof_bytes = moho_proof.0.receipt().proof().as_bytes().to_vec();
    let claim_unlock_bytes = encode_to_vec(&operator_claim_unlock)
        .map_err(|e| ExecutorError::AsmRpcErr(format!("encode claim_unlock: {e}")))?;
    let proof_input = BridgeProofInput {
        moho_state,
        moho_proof: moho_proof_bytes,
        claim_unlock: claim_unlock_bytes,
        claim_unlock_inclusion_proof: mmr_proof,
    };

    let receipt =
        prove::<BridgeProofProgram, _>(proof_input, output_handles.bridge_proof_host.clone())
            .await?;
    Ok(receipt.proof().as_bytes().to_vec())
}
