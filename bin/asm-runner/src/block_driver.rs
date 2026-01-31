//! Block driver that feeds Bitcoin blocks to the ASM worker

use std::{collections::VecDeque, sync::Arc};

use anyhow::Result;
use bitcoin::absolute::Height;
use bitcoind_async_client::{Client, traits::Reader};
use btc_tracker::{
    client::{BlockFetcher, BtcNotifyClient, Connected},
    event::BlockStatus,
};
use futures::StreamExt;
use strata_asm_worker::AsmWorkerHandle;
use strata_identifiers::{L1BlockCommitment, L1BlockId};
use strata_state::BlockSubmitter;
use tracing::{debug, error, info};

use crate::config::AsmRpcConfig;

/// Drive the ASM worker by subscribing to Bitcoin [`BlockEvent`](btc_tracker::event::BlockEvent).
///
/// This function subscribes to block events from the BTC tracker and submits
/// them to the ASM worker for processing.
pub(crate) async fn drive_asm_from_btc_tracker(
    btc_client: Arc<BtcNotifyClient<Connected>>,
    asm_worker: Arc<AsmWorkerHandle>,
) -> Result<()> {
    // Subscribe to block events
    let mut block_subscription = btc_client.subscribe_blocks().await;

    info!("Started ASM block driver, listening for Bitcoin blocks");

    // Process blocks as they arrive
    loop {
        let Some(block_event) = block_subscription.next().await else {
            tracing::warn!("Block subscription ended");
            break;
        };

        let block_height = block_event.block.bip34_block_height().unwrap_or(0);
        let block_hash = block_event.block.block_hash();

        info!(%block_height, %block_hash, status=?block_event.status, "received block event");

        // Only process buried blocks
        if matches!(block_event.status, BlockStatus::Buried) {
            // Construct L1BlockCommitment from block
            let block_id = L1BlockId::from(block_hash);
            let height = Height::from_consensus(block_height as u32).unwrap_or(Height::ZERO);
            let block_commitment = L1BlockCommitment::new(height, block_id);

            match asm_worker.submit_block_async(block_commitment).await {
                Ok(_) => {
                    debug!(%block_height, %block_hash, "submitted block to ASM worker");
                }
                Err(e) => {
                    error!(%block_height, %block_hash, error = ?e, "failed to submit block to ASM worker");
                }
            }
        }
    }

    Ok(())
}

/// Wrapper to implement BlockFetcher for bitcoind Client
struct BitcoinBlockFetcher {
    client: Arc<Client>,
}

#[async_trait::async_trait]
impl BlockFetcher for BitcoinBlockFetcher {
    type Error = anyhow::Error;

    async fn fetch_block(&self, height: u64) -> Result<bitcoin::Block, Self::Error> {
        let block_hash = self.client.get_block_hash(height).await?;
        Ok(self.client.get_block(&block_hash).await?)
    }
}

/// Setup BTC tracker client
pub(crate) async fn setup_btc_tracker(
    config: &AsmRpcConfig,
    bitcoin_client: Arc<Client>,
    start_height: u64,
) -> Result<BtcNotifyClient<Connected>> {
    let fetcher = BitcoinBlockFetcher {
        client: bitcoin_client,
    };

    let btc_tracker = BtcNotifyClient::new(&config.btc_tracker, VecDeque::new())
        .connect(start_height, fetcher)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to BTC tracker: {}", e))?;

    Ok(btc_tracker)
}
