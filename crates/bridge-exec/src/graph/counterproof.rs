//! Executor for the counterproof transaction.

use std::num::NonZero;

use bitcoin::{Transaction, TxOut, consensus};
use btc_tracker::event::TxStatus;
use musig2::secp256k1::schnorr::Signature;
use strata_bridge_connectors::prelude::ContestCounterproofWitness;
use strata_bridge_counterproof::{
    BitcoinTxOut, CounterproofInput, CounterproofProgram, RawBitcoinTx,
};
use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};
use strata_bridge_proof_common::prove;
use strata_bridge_tx_graph::transactions::counterproof::CounterproofTx;
use strata_mosaic_client_api::types::{G16ProofRaw, N_WITHDRAWAL_INPUT_WIRES};
use tracing::{info, warn};
use zkaleido::ProofReceipt;

use crate::{
    chain::publish_signed_transaction, errors::ExecutorError, output_handles::OutputHandles,
};

/// Generates the counterproof, completes adaptor signatures via mosaic,
/// assembles the witness with the pre-computed N-of-N signature, and publishes
/// the counterproof transaction to Bitcoin.
#[expect(clippy::too_many_arguments)]
pub(super) async fn generate_and_publish_counterproof(
    output_handles: &OutputHandles,
    counterproof_tx: CounterproofTx,
    operator_idx: OperatorIdx,
    deposit_idx: DepositIdx,
    game_index: NonZero<u32>,
    n_of_n_signature: Signature,
    bridge_proof_tx: Transaction,
    bridge_proof_tx_prevouts: Vec<TxOut>,
) -> Result<(), ExecutorError> {
    info!(%deposit_idx, %operator_idx, %game_index, "generating and publishing counterproof for graph");

    // TODO: <https://alpenlabs.atlassian.net/browse/STR-1981>
    // garble the receipt's proof into the wire-input representation.
    // Using mock counterproof data until that conversion is wired in.
    let _receipt = generate_counterproof(
        output_handles,
        deposit_idx,
        operator_idx,
        game_index,
        bridge_proof_tx,
        bridge_proof_tx_prevouts,
    )
    .await?;
    let counterproof_data = G16ProofRaw([0u8; N_WITHDRAWAL_INPUT_WIRES]);

    // Complete adaptor signatures via mosaic (we are the garbler/watchtower).
    info!(%deposit_idx, %operator_idx, "completing adaptor signatures via mosaic for graph");
    let completed_sigs = output_handles
        .mosaic_client
        .complete_adaptor_sigs(operator_idx, deposit_idx, counterproof_data)
        .await
        .map_err(|e| {
            warn!(?e, "failed to complete adaptor sigs for counterproof");
            ExecutorError::MosaicErr(format!("complete_adaptor_sigs: {e:?}"))
        })?;

    // The counterproof leaf script expects one operator signature per byte of counterproof
    // data (n_data = N_DEPOSIT + N_WITHDRAWAL wires), so we need ALL completed adaptor sigs.
    let operator_signatures = completed_sigs.to_vec();

    info!(%deposit_idx, %operator_idx, "signing and publishing counterproof tx for graph");

    // Assemble witness and finalize.
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

/// Fetches the prover inputs and generates the counterproof receipt.
async fn generate_counterproof(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    operator_idx: OperatorIdx,
    game_index: NonZero<u32>,
    bridge_proof_tx: Transaction,
    bridge_proof_tx_prevouts: Vec<TxOut>,
) -> Result<ProofReceipt, ExecutorError> {
    let proof_input = fetch_counterproof_input(
        output_handles,
        deposit_idx,
        operator_idx,
        game_index,
        bridge_proof_tx,
        bridge_proof_tx_prevouts,
    )
    .await?;

    info!(%deposit_idx, %operator_idx, "generating counterproof for graph");
    let prove_start = std::time::Instant::now();
    let receipt =
        prove::<CounterproofProgram, _>(proof_input, output_handles.counterproof_host.clone())
            .await?;
    info!(
        %deposit_idx,
        %operator_idx,
        elapsed = ?prove_start.elapsed(),
        "counterproof generated for graph",
    );

    Ok(receipt)
}

/// Fetches the inputs needed for counterproof generation and assembles them
/// into a [`CounterproofInput`] ready to feed into the counterproof program.
async fn fetch_counterproof_input(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    operator_idx: OperatorIdx,
    game_index: NonZero<u32>,
    bridge_proof_tx: Transaction,
    bridge_proof_tx_prevouts: Vec<TxOut>,
) -> Result<CounterproofInput, ExecutorError> {
    info!(%deposit_idx, %operator_idx, %game_index, "fetching counterproof inputs for graph");

    let operator_pubkey = output_handles
        .operator_table
        .idx_to_btc_key(&operator_idx)
        .expect("operator_idx must be present in the operator table")
        .x_only_public_key()
        .0
        .into();

    let bridge_proof_tx_prevouts = bridge_proof_tx_prevouts
        .into_iter()
        .map(BitcoinTxOut::from)
        .collect();

    Ok(CounterproofInput {
        game_idx: game_index.get(),
        operator_pubkey,
        bridge_proof_tx: RawBitcoinTx::from_raw_bytes(consensus::serialize(&bridge_proof_tx)),
        bridge_proof_tx_prevouts,
    })
}
