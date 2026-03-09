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
