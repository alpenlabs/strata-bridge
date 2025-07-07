use bitcoin::{Transaction, Txid};
use bitcoind_async_client::{traits::Broadcaster, Client};
use strata_bridge_common::tracing::info;

use crate::Args;

/// Create bitcoin [`Client`] from args.
pub(crate) fn create_bitcoin_client(args: &Args) -> Client {
    let max_retries = Some(3);
    let retry_interval = Some(3);
    Client::new(
        args.btc_url.clone(),
        args.btc_user.clone(),
        args.btc_pass.clone(),
        max_retries,
        retry_interval,
    )
    .expect("Could not create bitcoin client")
}

/// Publish given commit reveal txs to bitcoin.
pub(crate) async fn publish_txs(
    client: &Client,
    commit_tx: Transaction,
    reveal_tx: Transaction,
) -> anyhow::Result<(Txid, Txid)> {
    let commit_txid = client.send_raw_transaction(&commit_tx).await?;
    info!(%commit_txid, "published commit tx");

    let reveal_txid = client.send_raw_transaction(&reveal_tx).await?;
    info!(%reveal_txid, "published reveal tx");

    Ok((commit_txid, reveal_txid))
}
