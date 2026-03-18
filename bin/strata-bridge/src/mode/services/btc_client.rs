//! Provides initialization of clients related to bitcoin chain interaction.

use std::{collections::VecDeque, time::Duration};

use algebra::retry::{Strategy, retry_with};
use anyhow::anyhow;
use bitcoin::Block;
use bitcoind_async_client::{Auth, Client as BitcoinClient, error::ClientError, traits::Reader};
use btc_tracker::client::{BlockFetcher, BtcNotifyClient, Connected};

use crate::config::Config;

/// Initializes the Bitcoin RPC client using the provided configuration.
pub(in crate::mode) fn init_btc_rpc_client(config: &Config) -> anyhow::Result<BitcoinClient> {
    let auth = Auth::UserPass(
        config.btc_client.user.to_string(),
        config.btc_client.pass.to_string(),
    );

    BitcoinClient::new(
        config.btc_client.url.to_string(),
        auth,
        config.btc_client.retry_count,
        config.btc_client.retry_interval,
        None,
    )
    .map_err(|e| anyhow!("could not create bitcoin rpc client due to {e:?}"))
}

/// Initializes the ZMQ client for subscribing to Bitcoin (on-chain) events, starting from the
/// specified height.
pub(in crate::mode) async fn init_zmq_client(
    config: &Config,
    start_height: u64,
) -> anyhow::Result<BtcNotifyClient<Connected>> {
    // We have no awareness of what blocks are unburied at startup, so we start with an empty list.
    let unburied_blocks = VecDeque::new();
    let zmq_client = BtcNotifyClient::new(&config.btc_zmq, unburied_blocks);

    let btc_rpc_client = init_btc_rpc_client(config)?;
    zmq_client
        .connect(start_height, BtcFetcher(btc_rpc_client.clone()))
        .await
        .map_err(|e| anyhow!("zmq client could not connect to bitcoin node due to {e:?}"))
}

#[derive(Debug)]
struct BtcFetcher(BitcoinClient);

#[async_trait::async_trait]
impl BlockFetcher for BtcFetcher {
    type Error = ClientError;

    async fn fetch_block(&self, height: u64) -> Result<Block, Self::Error> {
        // TODO: <https://atlassian.alpenlabs.net/browse/STR-2664>
        // Make these retry settings configurable.
        const MAX_RETRIES: usize = 10;
        const INITIAL_DELAY: Duration = Duration::from_secs(1);
        const MAX_DELAY: Duration = Duration::from_secs(60);
        const MULTIPLIER: f64 = 2.0;

        let retry_strategy = Strategy::exponential_backoff(INITIAL_DELAY, MAX_DELAY, MULTIPLIER)
            .with_max_retries(MAX_RETRIES);

        let client = self.0.clone();
        retry_with(retry_strategy, move || {
            let client = client.clone();
            async move { client.get_block_at(height).await }
        })
        .await
    }
}
