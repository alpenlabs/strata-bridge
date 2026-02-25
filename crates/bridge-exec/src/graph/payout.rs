//! Executors for payout graph duties.

use bitcoin::Transaction;

use crate::{
    errors::ExecutorError, graph::utils::publish_singned_transaction, output_handles::OutputHandles,
};

/// Publishes the signed uncontested payout transaction to Bitcoin.
pub(super) async fn publish_uncontested_payout(
    output_handles: &OutputHandles,
    signed_uncontested_payout_tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_singned_transaction(
        output_handles,
        signed_uncontested_payout_tx,
        "uncontested payout",
    )
    .await
}

/// Publishes the signed contested payout transaction to Bitcoin.
pub(super) async fn publish_contested_payout(
    output_handles: &OutputHandles,
    signed_contested_payout_tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_singned_transaction(
        output_handles,
        signed_contested_payout_tx,
        "contested payout",
    )
    .await
}
