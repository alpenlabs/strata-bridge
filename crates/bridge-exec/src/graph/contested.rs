use std::num::NonZero;

use bitcoin::Transaction;
use btc_tracker::event::TxStatus;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_connectors::{Connector, prelude::ContestProofConnector};
use strata_bridge_tx_graph::transactions::bridge_proof::{BridgeProofData, BridgeProofTx};
use tracing::{info, warn};

use crate::{
    chain::publish_signed_transaction, errors::ExecutorError, output_handles::OutputHandles,
};

/// Generates a bridge proof transaction with mock proof data and publishes it.
pub(super) async fn generate_and_publish_bridge_proof(
    output_handles: &OutputHandles,
    contest_txid: bitcoin::Txid,
    game_index: NonZero<u32>,
    contest_proof_connector: ContestProofConnector,
) -> Result<(), ExecutorError> {
    info!(
        %contest_txid,
        %game_index,
        "generating and publishing bridge proof transaction"
    );

    // TODO: Replace with real ZK proof generation.
    let proof_bytes: Vec<u8> = vec![0u8; 32];

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
            operator_key_tweak.to_be_bytes(),
            tap_tweak,
        )
        .await
        .map_err(|e| {
            warn!(
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

/// Publishes the bridge proof timeout transaction to the Bitcoin network.
pub(super) async fn publish_bridge_proof_timeout(
    output_handles: &OutputHandles,
    signed_timeout_tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_signed_transaction(
        &output_handles.tx_driver,
        signed_timeout_tx,
        "bridge proof timeout",
        TxStatus::is_buried,
    )
    .await
}

/// Publishes the signed contested payout transaction to Bitcoin.
pub(super) async fn publish_contested_payout(
    output_handles: &OutputHandles,
    signed_contested_payout_tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_signed_transaction(
        &output_handles.tx_driver,
        signed_contested_payout_tx,
        "contested payout",
        TxStatus::is_buried,
    )
    .await
}
