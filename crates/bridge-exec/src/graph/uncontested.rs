//! Executors for payout graph duties.

use bitcoin::Transaction;

use crate::{
    errors::ExecutorError, graph::utils::publish_signed_transaction, output_handles::OutputHandles,
};

/// Publishes the signed uncontested payout transaction to Bitcoin.
pub(super) async fn publish_uncontested_payout(
    output_handles: &OutputHandles,
    signed_uncontested_payout_tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_signed_transaction(
        output_handles,
        signed_uncontested_payout_tx,
        "uncontested payout",
    )
    .await
}
