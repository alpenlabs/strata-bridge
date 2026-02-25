//! Shared helpers for graph executors.

use bitcoin::Transaction;
use btc_tracker::event::TxStatus;
use tracing::{info, warn};

use crate::{errors::ExecutorError, output_handles::OutputHandles};

/// Publishes a signed transaction to Bitcoin and waits for confirmation.
pub(crate) async fn publish_singned_transaction(
    output_handles: &OutputHandles,
    signed_tx: &Transaction,
    label: &str,
) -> Result<(), ExecutorError> {
    let txid = signed_tx.compute_txid();
    info!(%txid, %label, "publishing transaction");
    output_handles
        .tx_driver
        .drive(signed_tx.clone(), TxStatus::is_buried)
        .await
        .map_err(|e| {
            warn!(%txid, %label, ?e, "failed to publish transaction");
            ExecutorError::TxDriverErr(e)
        })?;
    info!(%txid, %label, "transaction confirmed");
    Ok(())
}
