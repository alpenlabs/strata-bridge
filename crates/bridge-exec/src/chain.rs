//! Shared Bitcoin chain helpers for executors.

use bitcoin::{Transaction, Txid};
use bitcoind_async_client::{Client as BitcoinClient, error::ClientError, traits::Reader};
use btc_tracker::{event::TxStatus, tx_driver::TxDriver};
use tracing::{debug, info, warn};

use crate::errors::ExecutorError;

/// Returns whether the provided transaction ID already exists on chain (confirmed or in the
/// mempool).
pub(crate) async fn is_txid_onchain(
    bitcoind_rpc_client: &BitcoinClient,
    txid: &Txid,
) -> Result<bool, ClientError> {
    debug!(%txid, "checking if tx is on chain");
    match bitcoind_rpc_client
        .get_raw_transaction_verbosity_one(txid)
        .await
    {
        Ok(_) => Ok(true),
        Err(e) if e.is_tx_not_found() => Ok(false),
        Err(e) => {
            warn!(%txid, ?e, "could not determine if tx is on chain");
            Err(e)
        }
    }
}

/// Publishes a signed transaction to Bitcoin and waits for the provided transaction status
/// condition to be met.
pub(crate) async fn publish_signed_transaction(
    tx_driver: &TxDriver,
    signed_tx: &Transaction,
    label: &str,
    wait_condition: fn(&TxStatus) -> bool,
) -> Result<(), ExecutorError> {
    let txid = signed_tx.compute_txid();
    info!(%txid, %label, "publishing transaction");

    tx_driver
        .drive(signed_tx.clone(), wait_condition)
        .await
        .map_err(|e| {
            warn!(%txid, %label, ?e, "failed to publish transaction");
            ExecutorError::TxDriverErr(e)
        })?;

    info!(%txid, %label, "transaction reached target status");
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::{Amount, Txid, hashes::Hash};
    use bitcoind_async_client::{Auth, Client as BitcoinClient};
    use corepc_node::{Conf, Node};

    use super::is_txid_onchain;

    fn setup_btc_client(bitcoind: &Node) -> BitcoinClient {
        let cookie = bitcoind
            .params
            .get_cookie_values()
            .expect("cookie file should be readable")
            .expect("cookie file should contain credentials");
        let auth = Auth::UserPass(cookie.user, cookie.password);

        BitcoinClient::new(bitcoind.rpc_url(), auth, None, None, None)
            .expect("async bitcoin rpc client should initialize")
    }

    fn missing_txid() -> Txid {
        Txid::from_slice(&[7; 32]).expect("txid bytes should be valid")
    }

    #[tokio::test]
    async fn is_txid_onchain_returns_false_for_missing_and_true_for_mined_transactions() {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");

        let bitcoind = Node::with_conf("bitcoind", &conf).expect("bitcoind should start");
        let mining_address = bitcoind
            .client
            .new_address()
            .expect("wallet address should be generated");
        bitcoind
            .client
            .generate_to_address(101, &mining_address)
            .expect("coinbase outputs should mature");

        let recipient = bitcoind
            .client
            .new_address()
            .expect("recipient address should be generated");
        let mined_txid = bitcoind
            .client
            .send_to_address(&recipient, Amount::ONE_BTC)
            .expect("wallet transaction should be created")
            .txid()
            .expect("wallet transaction result should expose a txid");
        bitcoind
            .client
            .generate_to_address(1, &mining_address)
            .expect("transaction should be mined");

        let rpc_client = setup_btc_client(&bitcoind);
        assert!(
            !is_txid_onchain(&rpc_client, &missing_txid())
                .await
                .expect("unknown txids should be treated as missing")
        );

        assert!(
            is_txid_onchain(&rpc_client, &mined_txid)
                .await
                .expect("mined transactions should be found")
        );

        assert!(
            is_txid_onchain(&rpc_client, &mined_txid)
                .await
                .expect("duplicate lookups should remain stable")
        );
    }
}
