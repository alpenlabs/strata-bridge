//! Block driver that feeds Bitcoin blocks to the ASM worker

use std::sync::Arc;

use anyhow::Result;
use bitcoin::absolute::Height;
use btc_tracker::{
    client::{BtcNotifyClient, Connected},
    event::BlockStatus,
};
use futures::StreamExt;
use strata_asm_worker::AsmWorkerHandle;
use strata_identifiers::{L1BlockCommitment, L1BlockId};
use strata_state::BlockSubmitter;

/// Drive the ASM worker by subscribing to Bitcoin block events from BtcTracker
///
/// This function subscribes to block events from the BTC tracker and submits
/// them to the ASM worker for processing.
pub(crate) async fn drive_asm_from_btc_tracker(
    btc_client: Arc<BtcNotifyClient<Connected>>,
    asm_worker: Arc<AsmWorkerHandle>,
) -> Result<()> {
    // Subscribe to block events
    let mut block_subscription = btc_client.subscribe_blocks().await;

    tracing::info!("Started ASM block driver, listening for Bitcoin blocks");

    // Process blocks as they arrive
    loop {
        let Some(block_event) = block_subscription.next().await else {
            tracing::warn!("Block subscription ended");
            break;
        };

        let block_height = block_event.block.bip34_block_height().unwrap_or(0);
        let block_hash = block_event.block.block_hash();

        tracing::info!(
            block_height = block_height,
            block_hash = %block_hash,
            status = ?block_event.status,
            "received block event"
        );

        // Only process buried blocks
        if matches!(block_event.status, BlockStatus::Buried) {
            // Construct L1BlockCommitment from block
            let block_id = L1BlockId::from(block_hash);
            let height = Height::from_consensus(block_height as u32).unwrap_or(Height::ZERO);
            let block_commitment = L1BlockCommitment::new(height, block_id);

            match asm_worker.submit_block_async(block_commitment).await {
                Ok(_) => {
                    tracing::debug!(
                        block_height = block_height,
                        block_hash = %block_hash,
                        "submitted block to ASM worker"
                    );
                }
                Err(e) => {
                    tracing::error!(
                        block_height = block_height,
                        block_hash = %block_hash,
                        error = ?e,
                        "failed to submit block to ASM worker"
                    );
                }
            }
        }
    }

    Ok(())
}
