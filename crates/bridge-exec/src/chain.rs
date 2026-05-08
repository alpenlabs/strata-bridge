//! Shared Bitcoin chain helpers for executors.

use bitcoin::{OutPoint, Transaction, Txid};
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

/// Returns whether `outpoint` is currently unspent on chain or in the mempool.
///
/// Wraps Bitcoin Core's `gettxout`. A `null` result (spent or non-existent UTXO) maps to
/// `Ok(false)`; transport, RPC, or parse failures propagate as `Err` so callers do not mistake a
/// transient blip for a confirmed spend.
pub(crate) async fn is_outpoint_unspent(
    bitcoind_rpc_client: &BitcoinClient,
    outpoint: &OutPoint,
) -> Result<bool, ClientError> {
    debug!(%outpoint, "checking if outpoint is unspent");
    match bitcoind_rpc_client
        .get_tx_out(&outpoint.txid, outpoint.vout, true)
        .await
    {
        Ok(_) => Ok(true),
        // bitcoind returns `null` for a spent or non-existent UTXO; the client surfaces that
        // through this specific `Other` variant because the JSON-RPC response carries no `result`
        // field.
        Err(ClientError::Other(ref msg)) if msg == "Empty data received" => Ok(false),
        Err(e) => {
            warn!(%outpoint, ?e, "could not determine if outpoint is unspent");
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
    use bitcoin::{
        Amount, OutPoint, Transaction, Txid, consensus::encode::deserialize_hex, hashes::Hash,
    };
    use bitcoind_async_client::{Auth, Client as BitcoinClient, traits::Reader};
    use corepc_node::{Conf, Input, Node, Output};

    use super::{is_outpoint_unspent, is_txid_onchain};

    /// Per-coinbase reward on regtest before any halving.
    const REGTEST_COINBASE_AMOUNT: Amount = Amount::from_sat(50 * 100_000_000);

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

    /// Tracks the source outpoint of a single spending transaction across its
    /// full lifecycle — locally signed (not broadcast), in mempool, and mined —
    /// and asserts both `is_outpoint_unspent` and the spending tx's
    /// confirmation count at each stage. Also covers the missing-outpoint case.
    #[tokio::test]
    async fn is_outpoint_unspent_tracks_spending_tx_lifecycle() {
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

        let rpc_client = setup_btc_client(&bitcoind);

        // The matured coinbase output is the source outpoint we'll track.
        let first_block = rpc_client
            .get_block_at(1)
            .await
            .expect("first mined block should be retrievable");
        let coinbase_tx = first_block
            .coinbase()
            .expect("first mined block should contain a coinbase transaction");
        let source_outpoint = OutPoint {
            txid: coinbase_tx.compute_txid(),
            vout: 0,
        };

        // Outpoints whose txid does not exist on chain are reported as not unspent.
        let missing_outpoint = OutPoint {
            txid: missing_txid(),
            vout: 0,
        };
        assert!(
            !is_outpoint_unspent(&rpc_client, &missing_outpoint)
                .await
                .expect("rpc call should succeed for missing outpoint"),
            "missing outpoint should be reported as not unspent"
        );

        // Build a spending tx that sweeps the coinbase to a fresh wallet address
        // (minus a small fee). With only one matured UTXO available, this is the
        // only spend the wallet can produce.
        let recipient = bitcoind
            .client
            .new_address()
            .expect("recipient address should be generated");
        let inputs = [Input {
            txid: source_outpoint.txid,
            vout: u64::from(source_outpoint.vout),
            sequence: None,
        }];
        let outputs = [Output::new(
            recipient,
            Amount::from_sat(REGTEST_COINBASE_AMOUNT.to_sat() - 2_000),
        )];
        let unsigned_tx = bitcoind
            .client
            .create_raw_transaction(&inputs, &outputs)
            .expect("create raw tx")
            .transaction()
            .expect("decode unsigned tx");

        let signed = bitcoind
            .client
            .sign_raw_transaction_with_wallet(&unsigned_tx)
            .expect("wallet should sign the spending tx");
        assert!(
            signed.complete,
            "wallet should produce a complete signature"
        );
        let signed_tx: Transaction =
            deserialize_hex(&signed.hex).expect("signed tx hex should deserialize");
        let spending_txid = signed_tx.compute_txid();

        // STAGE 1: signed locally but not broadcast.
        // Source outpoint is still unspent. Spending tx is unknown to the node.
        assert!(
            is_outpoint_unspent(&rpc_client, &source_outpoint)
                .await
                .expect("rpc call must succeed"),
            "stage 1 (unbroadcast): source outpoint should still be unspent"
        );
        assert!(
            rpc_client
                .get_raw_transaction_verbosity_one(&spending_txid)
                .await
                .is_err(),
            "stage 1 (unbroadcast): spending tx should not be retrievable"
        );

        // STAGE 2: broadcast to mempool, not yet mined.
        // Source outpoint is reported as spent because we query gettxout with
        // include_mempool=true. Spending tx exists with no confirmations.
        bitcoind
            .client
            .send_raw_transaction(&signed_tx)
            .expect("broadcast spending tx");
        assert!(
            !is_outpoint_unspent(&rpc_client, &source_outpoint)
                .await
                .expect("rpc"),
            "stage 2 (mempool): source outpoint should be reported as spent"
        );
        let mempool_status = rpc_client
            .get_raw_transaction_verbosity_one(&spending_txid)
            .await
            .expect("spending tx should be retrievable from mempool");
        assert_eq!(
            mempool_status.confirmations, None,
            "stage 2 (mempool): spending tx should have no confirmations"
        );

        // STAGE 3: mined.
        // Source outpoint is consumed on chain. Spending tx has at least one
        // confirmation.
        bitcoind
            .client
            .generate_to_address(1, &mining_address)
            .expect("mine the spending tx");
        assert!(
            !is_outpoint_unspent(&rpc_client, &source_outpoint)
                .await
                .expect("rpc"),
            "stage 3 (mined): source outpoint should be reported as spent"
        );
        let mined_status = rpc_client
            .get_raw_transaction_verbosity_one(&spending_txid)
            .await
            .expect("mined spending tx should be retrievable");
        assert!(
            mined_status.confirmations.is_some_and(|c| c >= 1),
            "stage 3 (mined): spending tx should have ≥1 confirmation, got {:?}",
            mined_status.confirmations
        );
    }
}
