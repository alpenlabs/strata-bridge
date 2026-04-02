use bitcoin::Transaction;
use btc_tracker::event::TxStatus;

use crate::{
    chain::publish_signed_transaction, errors::ExecutorError, output_handles::OutputHandles,
};

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

/// Publishes the signed counterproof ACK transaction to Bitcoin.
pub(super) async fn publish_counterproof_ack(
    output_handles: &OutputHandles,
    signed_counter_proof_ack_tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_signed_transaction(
        &output_handles.tx_driver,
        signed_counter_proof_ack_tx,
        "counterproof ack",
        TxStatus::is_buried,
    )
    .await
}

/// Publishes the signed slash transaction to Bitcoin.
pub(super) async fn publish_slash(
    output_handles: &OutputHandles,
    signed_slash_tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_signed_transaction(
        &output_handles.tx_driver,
        signed_slash_tx,
        "slash",
        TxStatus::is_buried,
    )
    .await
}
