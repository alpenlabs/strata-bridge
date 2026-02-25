//! Executors for payout graph duties.

use bitcoin::Transaction;
use btc_tracker::event::TxStatus;
use tracing::{info, warn};

use crate::{errors::ExecutorError, output_handles::OutputHandles};

/// Publishes the signed uncontested payout transaction to Bitcoin.
pub(super) async fn publish_uncontested_payout(
    output_handles: &OutputHandles,
    signed_uncontested_payout_tx: &Transaction,
) -> Result<(), ExecutorError> {
    let payout_txid = signed_uncontested_payout_tx.compute_txid();
    info!(%payout_txid, "publishing uncontested payout transaction");

    output_handles
        .tx_driver
        .drive(signed_uncontested_payout_tx.clone(), TxStatus::is_buried)
        .await
        .map_err(|e| {
            warn!(%payout_txid, ?e, "failed to publish uncontested payout transaction");
            ExecutorError::TxDriverErr(e)
        })?;

    info!(%payout_txid, "uncontested payout confirmed");
    Ok(())
}

/// Publishes the signed contested payout transaction to Bitcoin.
pub(super) async fn publish_contested_payout(
    output_handles: &OutputHandles,
    signed_contested_payout_tx: &Transaction,
) -> Result<(), ExecutorError> {
    let payout_txid = signed_contested_payout_tx.compute_txid();
    info!(%payout_txid, "publishing contested payout transaction");

    output_handles
        .tx_driver
        .drive(signed_contested_payout_tx.clone(), TxStatus::is_buried)
        .await
        .map_err(|e| {
            warn!(%payout_txid, ?e, "failed to publish contested payout transaction");
            ExecutorError::TxDriverErr(e)
        })?;

    info!(%payout_txid, "contested payout confirmed");
    Ok(())
}
