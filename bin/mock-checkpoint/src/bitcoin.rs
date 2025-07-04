use bitcoin::{Transaction, Txid};
use bitcoind_async_client::{traits::Broadcaster, Client};

use crate::Args;

/// Create bitcoin [`Client`] from args.
pub(crate) fn create_bitcoin_client(args: &Args) -> Client {
    let max_retries = Some(3);
    let retry_interval = Some(3);
    Client::new(
        args.bitcoin_url.clone(),
        args.bitcoin_username.clone(),
        args.bitcoin_password.clone(),
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
    println!("Publishing commit tx");
    let commit_txid = client.send_raw_transaction(&commit_tx).await?;
    println!("Published commit tx: {commit_txid}");

    println!("Publishing reveal tx");
    let reveal_txid = client.send_raw_transaction(&reveal_tx).await?;
    println!("Published reveal tx: {reveal_txid}");

    Ok((commit_txid, reveal_txid))
}
