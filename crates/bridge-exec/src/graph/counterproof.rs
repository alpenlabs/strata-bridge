//! Executor for the counterproof transaction.

use std::num::NonZero;

use bitcoin::{Amount, Network, ScriptBuf, Transaction, consensus, relative};
use bitcoind_async_client::{error::ClientError, traits::Reader};
use btc_tracker::event::TxStatus;
use musig2::secp256k1::schnorr::Signature;
use strata_bridge_connectors::prelude::{ContestCounterproofWitness, ContestProofConnector};
use strata_bridge_counterproof::{
    BitcoinTxOut, BridgeCounterproofHost, CounterproofInput, CounterproofMode, CounterproofProgram,
    RawBitcoinTx,
};
use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};
use strata_bridge_proof_common::prove;
use strata_bridge_tx_graph::transactions::counterproof::CounterproofTx;
use strata_mosaic_client_api::types::{G16ProofRaw, N_WITHDRAWAL_INPUT_WIRES};
use tracing::{info, warn};
#[cfg(feature = "sp1")]
use zkaleido_sp1_groth16_verifier::Sp1Groth16Proof;

use crate::{
    chain::publish_signed_transaction, config::ExecutionConfig, errors::ExecutorError,
    output_handles::OutputHandles,
};

/// Generates the counterproof, completes adaptor signatures via mosaic,
/// assembles the witness with the pre-computed N-of-N signature, and publishes
/// the counterproof transaction to Bitcoin.
#[expect(clippy::too_many_arguments)]
pub(super) async fn generate_and_publish_counterproof(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    counterproof_tx: CounterproofTx,
    operator_idx: OperatorIdx,
    deposit_idx: DepositIdx,
    game_index: NonZero<u32>,
    n_of_n_signature: Signature,
    bridge_proof_tx: Transaction,
) -> Result<(), ExecutorError> {
    info!(%deposit_idx, %operator_idx, %game_index, "generating and publishing counterproof for graph");

    let counterproof_data = generate_counterproof(
        cfg,
        output_handles,
        deposit_idx,
        operator_idx,
        game_index,
        bridge_proof_tx,
    )
    .await?;

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

/// Prepares the prover inputs and generates the counterproof, returning the
/// [`G16ProofRaw`].
///
/// Under the SP1 host, the receipt's SP1-wrapped Groth16 proof is unwrapped
/// and gnark-compressed into a [`G16ProofRaw`]. Under the native host a zero-filled [`G16ProofRaw`]
/// is returned as a stand-in.
async fn generate_counterproof(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    operator_idx: OperatorIdx,
    game_index: NonZero<u32>,
    bridge_proof_tx: Transaction,
) -> Result<G16ProofRaw, ExecutorError> {
    let proof_input = fetch_counterproof_input(
        cfg,
        output_handles,
        deposit_idx,
        operator_idx,
        game_index,
        bridge_proof_tx,
    )
    .await?;

    info!(%deposit_idx, %operator_idx, "generating counterproof for graph");
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
        %operator_idx,
        elapsed = ?prove_start.elapsed(),
        "counterproof generated for graph",
    );

    Ok(counterproof_data)
}

/// Fetches the inputs needed for counterproof generation and assembles them
/// into a [`CounterproofInput`] ready to feed into the counterproof program.
async fn fetch_counterproof_input(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    operator_idx: OperatorIdx,
    game_index: NonZero<u32>,
    bridge_proof_tx: Transaction,
) -> Result<CounterproofInput, ExecutorError> {
    info!(%deposit_idx, %operator_idx, %game_index, "fetching counterproof inputs for graph");

    let operator_xonly = output_handles
        .operator_table
        .idx_to_btc_key(&operator_idx)
        .expect("operator_idx must be present in the operator table")
        .x_only_public_key()
        .0;

    let n_of_n_xonly = output_handles
        .operator_table
        .aggregated_btc_key()
        .x_only_public_key()
        .0;

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
        bridge_proof_tx_prevouts.push(BitcoinTxOut::from(prevout));
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
        mode: CounterproofMode::InvalidBridgeProof,
    })
}
