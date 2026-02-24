use btc_tracker::event::TxStatus;
use tracing::info;

use crate::{errors::ExecutorError, output_handles::OutputHandles};

/// Publishes the bridge proof timeout transaction to the Bitcoin network.
pub(super) async fn publish_bridge_proof_timeout(
    output_handles: &OutputHandles,
    signed_timeout_tx: bitcoin::Transaction,
) -> Result<(), ExecutorError> {
    let txid = signed_timeout_tx.compute_txid();
    info!(%txid, "publishing the bridge proof timeout transaction");

    output_handles
        .tx_driver
        .drive(signed_timeout_tx, TxStatus::is_buried)
        .await?;

    info!(%txid, "bridge proof timeout transaction is confirmed");
    Ok(())
}
