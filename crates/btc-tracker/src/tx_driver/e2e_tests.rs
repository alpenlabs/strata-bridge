//! End-to-end tests of the transaction driver against a bitcoind node.

use std::{collections::VecDeque, path::PathBuf, sync::Arc, time::Duration};

use algebra::predicate;
use bitcoin::{
    absolute, transaction, Amount, Block, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Witness,
};
use bitcoind_async_client::Client as BitcoinClient;
use corepc_node::{client::client_sync::Auth, vtype::FundRawTransaction, CookieValues, Output};
use futures::{join, TryFutureExt};
use serial_test::serial;
use strata_bridge_common::logging;
use strata_bridge_test_utils::prelude::wait_for_height;
use tracing::{debug, info};

use super::{driver::*, *};
use crate::{
    client::{BlockFetcher, BtcNotifyClient},
    config::BtcNotifyConfig,
    event::TxStatus,
};

// TODO: <https://alpenlabs.atlassian.net/browse/STR-2692>
// Remove this once rust-bitcoin@0.33.x lands; it works around a rust-bitcoin bug.
pub(crate) const BIP34_MIN_BLOCKS: usize = 17;

fn setup_fetcher(rpc_url: &str, cookie_file: PathBuf) -> impl BlockFetcher<Error = String> {
    struct Fetcher(corepc_node::Client);

    #[async_trait::async_trait]
    impl BlockFetcher for Fetcher {
        type Error = String;

        async fn fetch_block(&self, height: u64) -> Result<Block, Self::Error> {
            let hash = self
                .0
                .get_block_hash(height)
                .map_err(|e| e.to_string())?
                .block_hash()
                .expect("must be valid hash");
            let block = self.0.get_block(hash).map_err(|e| e.to_string())?;

            Ok(block)
        }
    }

    let auth = Auth::CookieFile(cookie_file);
    let client =
        corepc_node::Client::new_with_auth(rpc_url, auth).expect("must be able to create client");

    Fetcher(client)
}

async fn setup() -> Result<(TxDriver, corepc_node::Node), Box<dyn std::error::Error>> {
    let mut bitcoin_conf = corepc_node::Conf::default();
    bitcoin_conf.enable_zmq = true;

    // TODO: <https://alpenlabs.atlassian.net/browse/STR-2681>
    // Use dynamic port allocation so these tests can run in parallel.
    let hash_block_socket = "tcp://127.0.0.1:23882";
    let hash_tx_socket = "tcp://127.0.0.1:23883";
    let raw_block_socket = "tcp://127.0.0.1:23884";
    let raw_tx_socket = "tcp://127.0.0.1:23885";
    let sequence_socket = "tcp://127.0.0.1:23886";
    let args = [
        format!("-zmqpubhashblock={hash_block_socket}"),
        format!("-zmqpubhashtx={hash_tx_socket}"),
        format!("-zmqpubrawblock={raw_block_socket}"),
        format!("-zmqpubrawtx={raw_tx_socket}"),
        format!("-zmqpubsequence={sequence_socket}"),
        // NOTE: (@Rajil1213) without this, the node will respond with status code 500
        // when rebroadcasting or querying for mined transactions, causing idempotence tests to
        // fail or become flaky.
        "-txindex=1".to_string(),
    ];
    bitcoin_conf.args.extend(args.iter().map(String::as_str));
    let bitcoind = corepc_node::Node::with_conf("bitcoind", &bitcoin_conf)?;

    bitcoind
        .client
        .generate_to_address(BIP34_MIN_BLOCKS, &bitcoind.client.new_address()?)?;

    debug!("corepc_node::Node initialized");

    let cfg = BtcNotifyConfig::default()
        .with_hashblock_connection_string(hash_block_socket)
        .with_hashtx_connection_string(hash_tx_socket)
        .with_rawblock_connection_string(raw_block_socket)
        .with_rawtx_connection_string(raw_tx_socket)
        .with_sequence_connection_string(sequence_socket);

    let zmq_client = BtcNotifyClient::new(&cfg, VecDeque::new());
    let start_height = bitcoind.client.get_block_count()?.0;
    let cookie_file = bitcoind.params.cookie_file.clone();
    let fetcher = setup_fetcher(&bitcoind.rpc_url(), cookie_file);
    let zmq_client = zmq_client.connect(start_height, fetcher).await?;
    debug!("BtcNotifyClient initialized");

    let CookieValues { user, password } = bitcoind
        .params
        .get_cookie_values()
        .expect("can read cookie")
        .expect("can parse cookie");
    let auth = bitcoind_async_client::Auth::UserPass(user, password);
    let rpc_client = BitcoinClient::new(bitcoind.rpc_url(), auth, None, None, None)
        .expect("can set up rpc client");
    debug!("bitcoin_async_client::Client initialized");

    let tx_driver = TxDriver::new(zmq_client, rpc_client).await;
    debug!("TxDriver initialized");

    Ok((tx_driver, bitcoind))
}

#[tokio::test]
#[serial]
async fn tx_drive_idempotence() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_from_env("tx_drive_idempotence");

    let (driver, bitcoind) = setup().await?;

    let new_address = bitcoind.client.new_address()?;
    // Mine 101 new blocks to that same address. We use 101 so that the coins minted in the
    // first block can be spent which we will need to do for the remainder of the test.
    let _ = bitcoind
        .client
        .generate_to_address(101, &new_address)?
        .into_model()?;
    debug!("waiting for test funds to mature");
    wait_for_height(&bitcoind, 101).await?;
    debug!("test funds matured");

    debug!("creating raw transaction");
    let out = Output::new(new_address.clone(), Amount::from_btc(1.0)?);
    // Get hex string directly - don't use into_model() as 0-input transactions
    // can't be deserialized due to segwit marker ambiguity
    let raw_hex = bitcoind.client.create_raw_transaction(&[], &[out])?.0;
    debug!(%raw_hex, "created raw transaction");

    debug!("funding raw transaction");
    // Use call() directly to pass hex string since fund_raw_transaction expects &Transaction
    let funded_result: FundRawTransaction = bitcoind
        .client
        .call("fundrawtransaction", &[raw_hex.into()])?;
    let funded = funded_result.into_model()?.tx;
    debug!(funded=%funded.compute_txid(), "funded raw transaction");

    debug!("signing raw transaction");
    let signed = bitcoind
        .client
        .sign_raw_transaction_with_wallet(&funded)?
        .into_model()?
        .tx;
    debug!(signed=%signed.compute_txid(), "signed raw transaction");

    info!("sending first copy to TxDriver");
    let fst = driver.drive(signed.clone(), TxStatus::is_buried);
    info!("sending second copy to TxDriver");
    let snd = driver.drive(signed, TxStatus::is_buried);

    info!("starting mining task");
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_thread = stop.clone();
    let mine_task = tokio::task::spawn_blocking(move || {
        while !stop_thread.load(std::sync::atomic::Ordering::SeqCst) {
            bitcoind
                .client
                .generate_to_address(1, &new_address)
                .unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
    });

    debug!("waiting for TxDriver::drive calls to complete");
    let (fst_res, snd_res) = join!(fst, snd);
    info!("TxDriver::drive calls completed");

    debug!("terminating mining task");
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    tokio::time::timeout(std::time::Duration::from_secs(1), mine_task).await??;
    info!("mining task terminated");

    fst_res.expect("first drive succeeds");
    snd_res.expect("second drive succeeds");

    Ok(())
}

/// A wallet payment of 1 BTC to `address`, funded and signed by the node's wallet.
fn signed_payment(
    bitcoind: &corepc_node::Node,
    address: bitcoin::Address,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let outs = vec![Output::new(address, Amount::from_btc(1.0)?)];
    let raw_hex = bitcoind.client.create_raw_transaction(&[], &outs)?.0;
    let funded: FundRawTransaction = bitcoind
        .client
        .call("fundrawtransaction", &[raw_hex.into()])?;
    Ok(bitcoind
        .client
        .sign_raw_transaction_with_wallet(&funded.into_model()?.tx)?
        .into_model()?
        .tx)
}

/// A caller whose condition the transaction never meets hears `ConditionUnmet` at burial,
/// rather than waiting for an event that a buried transaction never sends.
#[tokio::test]
#[serial]
async fn tx_drive_condition_unmet_at_burial() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_from_env("tx_drive_condition_unmet_at_burial");

    let (driver, bitcoind) = setup().await?;
    let address = bitcoind.client.new_address()?;
    bitcoind.client.generate_to_address(101, &address)?;
    wait_for_height(&bitcoind, 101).await?;
    let signed = signed_payment(&bitcoind, address.clone())?;

    let never = driver.drive(signed.clone(), |_| false);
    let bury = async {
        driver
            .drive(signed.clone(), predicate::eq(TxStatus::Mempool))
            .await?;
        bitcoind
            .client
            .generate_to_address(crate::constants::DEFAULT_BURY_DEPTH + 2, &address)?;
        Ok::<(), Box<dyn std::error::Error>>(())
    };

    let (never_result, buried) =
        tokio::time::timeout(Duration::from_secs(60), futures::future::join(never, bury))
            .await
            .expect("a wait that can never be met must end at burial");
    buried?;

    assert!(
        matches!(never_result, Err(DriveErr::ConditionUnmet)),
        "the caller must hear that its condition went unmet, got {never_result:?}"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn tx_drive_mempool() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_from_env("tx_drive_idempotence");

    let (driver, bitcoind) = setup().await?;

    let new_address = bitcoind.client.new_address()?;
    // Mine 101 new blocks to that same address. We use 101 so that the coins minted in the
    // first block can be spent which we will need to do for the remainder of the test.
    let _ = bitcoind
        .client
        .generate_to_address(101, &new_address)?
        .into_model()?;
    debug!("waiting for test funds to mature");
    wait_for_height(&bitcoind, 101).await?;
    debug!("test funds matured");

    debug!("creating raw transaction");
    let outs = vec![Output::new(new_address, Amount::from_btc(1.0)?)];
    // Get hex string directly - don't use into_model() as 0-input transactions
    // can't be deserialized due to segwit marker ambiguity
    let raw_hex = bitcoind.client.create_raw_transaction(&[], &outs)?.0;
    debug!(%raw_hex, "created raw transaction");

    debug!("funding raw transaction");
    // Use call() directly to pass hex string since fund_raw_transaction expects &Transaction
    let funded_result: FundRawTransaction = bitcoind
        .client
        .call("fundrawtransaction", &[raw_hex.into()])?;
    let funded = funded_result.into_model()?.tx;
    debug!(funded=%funded.compute_txid(), "funded raw transaction");

    debug!("signing raw transaction");
    let signed = bitcoind
        .client
        .sign_raw_transaction_with_wallet(&funded)?
        .into_model()?
        .tx;
    debug!(signed=%signed.compute_txid(), "signed raw transaction");

    info!("driving to mempool");
    driver
        .drive(signed, predicate::eq(TxStatus::Mempool))
        .await?;
    info!("transaction appeared in mempool");

    Ok(())
}

#[tokio::test]
#[serial]
async fn tx_drive_op_return_burn() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_from_env("tx_drive_op_return_burn");

    let (driver, bitcoind) = setup().await?;

    let new_address = bitcoind.client.new_address()?;
    let blocks = bitcoind
        .client
        .generate_to_address(101, &new_address)?
        .into_model()?;
    debug!("waiting for test funds to mature");
    wait_for_height(&bitcoind, 101).await?;
    debug!("test funds matured");

    let spendable_block = bitcoind.client.get_block(
        *blocks
            .0
            .first()
            .expect("generate_to_address must return mined block hashes"),
    )?;
    let coinbase_tx = spendable_block
        .coinbase()
        .expect("mined block must contain a coinbase transaction");

    let burn_amount = Amount::from_sat(1_000);
    let fee = Amount::from_sat(10_000);
    let change_amount = coinbase_tx.output[0].value - burn_amount - fee;
    let change_address = bitcoind.client.new_address()?;
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(coinbase_tx.compute_txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![
            TxOut {
                value: burn_amount,
                script_pubkey: ScriptBuf::new_op_return([1u8; 32]),
            },
            TxOut {
                value: change_amount,
                script_pubkey: change_address.script_pubkey(),
            },
        ],
    };

    let signed = bitcoind
        .client
        .sign_raw_transaction_with_wallet(&unsigned)?
        .into_model()?
        .tx;

    let err = bitcoind
        .client
        .send_raw_transaction(&signed)
        .expect_err("default maxburnamount must reject OP_RETURN burns");
    let err = err.to_string();
    assert!(
        err.contains("maxburnamount") || err.contains("max-burn-amount"),
        "unexpected sendrawtransaction error: {err}"
    );

    info!("driving OP_RETURN burn to mempool");
    driver
        .drive(signed.clone(), predicate::eq(TxStatus::Mempool))
        .await?;
    info!("OP_RETURN burn transaction appeared in mempool");

    Ok(())
}

// Spends `prevout` (worth `input_value`) back to `recipient` with RBF enabled, paying `fee`.
fn sign_rbf_spend(
    bitcoind: &corepc_node::Node,
    prevout: OutPoint,
    input_value: Amount,
    recipient: &bitcoin::Address,
    fee: Amount,
) -> Result<Transaction, Box<dyn std::error::Error>> {
    let unsigned = Transaction {
        version: transaction::Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: prevout,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: input_value - fee,
            script_pubkey: recipient.script_pubkey(),
        }],
    };

    Ok(bitcoind
        .client
        .sign_raw_transaction_with_wallet(&unsigned)?
        .into_model()?
        .tx)
}

// Mines 101 blocks to `address` and returns the first block's matured coinbase outpoint and
// value.
async fn mature_coinbase(
    bitcoind: &corepc_node::Node,
    address: &bitcoin::Address,
) -> Result<(OutPoint, Amount), Box<dyn std::error::Error>> {
    let blocks = bitcoind
        .client
        .generate_to_address(101, address)?
        .into_model()?;
    debug!("waiting for test funds to mature");
    wait_for_height(bitcoind, 101).await?;
    debug!("test funds matured");

    let spendable_block = bitcoind.client.get_block(
        *blocks
            .0
            .first()
            .expect("generate_to_address must return mined block hashes"),
    )?;
    let coinbase_tx = spendable_block
        .coinbase()
        .expect("mined block must contain a coinbase transaction");

    Ok((
        OutPoint::new(coinbase_tx.compute_txid(), 0),
        coinbase_tx.output[0].value,
    ))
}

// An evicted transaction whose rebroadcast is rejected fails the drive job.
#[tokio::test]
#[serial]
async fn tx_drive_eviction() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_from_env("tx_drive_eviction");

    let (driver, bitcoind) = setup().await?;

    let new_address = bitcoind.client.new_address()?;
    let (prevout, input_value) = mature_coinbase(&bitcoind, &new_address).await?;

    // Two conflicting spends of the same output. The first pays a low fee and signals RBF, the
    // second pays enough more to replace it and knock the first out of the mempool.
    let evicted_tx = sign_rbf_spend(
        &bitcoind,
        prevout,
        input_value,
        &new_address,
        Amount::from_sat(1_000),
    )?;
    let replacement_tx = sign_rbf_spend(
        &bitcoind,
        prevout,
        input_value,
        &new_address,
        Amount::from_sat(50_000),
    )?;
    let evicted_txid = evicted_tx.compute_txid();

    info!(%evicted_txid, "driving low-fee transaction to burial");
    let drive_to_buried = driver.drive(evicted_tx.clone(), TxStatus::is_buried);

    let replace = async {
        driver
            .drive(evicted_tx.clone(), predicate::eq(TxStatus::Mempool))
            .await?;
        // Give the ZMQ client a moment to record the transaction's lifecycle. If the removal
        // below were processed before the acceptance, no `Unknown` event would be emitted.
        tokio::time::sleep(Duration::from_secs(1)).await;

        info!(replacement_txid = %replacement_tx.compute_txid(), "broadcasting replacement");
        bitcoind.client.send_raw_transaction(&replacement_tx)?;

        Ok::<(), Box<dyn std::error::Error>>(())
    };

    let (drive_result, replace_result) = tokio::time::timeout(
        Duration::from_secs(60),
        futures::future::join(drive_to_buried, replace),
    )
    .await
    .expect("drive must resolve after eviction");
    replace_result?;

    match drive_result {
        Err(DriveErr::Evicted { txid, source }) => {
            assert_eq!(txid, evicted_txid);
            assert!(
                source.is_rpc_verify_rejected(),
                "rebroadcast of a replaced tx must be a policy rejection, got {source:?}"
            );
        }
        other => panic!("expected an eviction error, got {other:?}"),
    }

    Ok(())
}

// A reorg that swaps the transaction's block for a sibling that also includes it evicts the
// transaction while it is still on chain. A child in both blocks spends its only output, so
// the rebroadcast is rejected for missing inputs and the drive job must survive until burial.
#[tokio::test]
#[serial]
async fn tx_drive_reorg_onto_sibling() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_from_env("tx_drive_reorg_onto_sibling");

    let (driver, bitcoind) = setup().await?;

    let new_address = bitcoind.client.new_address()?;
    let (prevout, input_value) = mature_coinbase(&bitcoind, &new_address).await?;

    let fee = Amount::from_sat(10_000);
    let signed = sign_rbf_spend(&bitcoind, prevout, input_value, &new_address, fee)?;
    let txid = signed.compute_txid();

    info!(%txid, "driving transaction to burial across a sibling reorg");
    let drive_to_buried = driver
        .drive(signed.clone(), TxStatus::is_buried)
        .map_err(|e| Box::new(e) as Box<dyn std::error::Error>);

    let reorg_then_bury = async {
        driver
            .drive(signed.clone(), predicate::eq(TxStatus::Mempool))
            .await?;
        // The wallet can only sign the child once it knows the transaction it spends.
        let child = sign_rbf_spend(
            &bitcoind,
            OutPoint::new(txid, 0),
            input_value - fee,
            &new_address,
            fee,
        )?;
        bitcoind.client.send_raw_transaction(&child)?;
        tokio::time::sleep(Duration::from_secs(1)).await;

        let first = bitcoind
            .client
            .generate_to_address(1, &new_address)?
            .into_model()?
            .0
            .remove(0);
        driver.drive(signed.clone(), TxStatus::is_mined).await?;
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Move the transaction (and its child, which bitcoind re-adds with it) into a sibling
        // of `first`. Regtest clamps block timestamps to median-time-past + 1 when blocks are
        // mined this quickly, so the extra wallet transaction keeps the sibling from
        // reproducing `first` exactly, which the node would reject.
        bitcoind
            .client
            .call::<()>("invalidateblock", &[first.to_string().into()])?;
        driver
            .drive(signed.clone(), predicate::eq(TxStatus::Mempool))
            .await?;
        bitcoind
            .client
            .send_to_address(&new_address, Amount::ONE_BTC)?;
        let sibling = bitcoind
            .client
            .generate_to_address(1, &new_address)?
            .into_model()?
            .0
            .remove(0);
        driver.drive(signed.clone(), TxStatus::is_mined).await?;
        tokio::time::sleep(Duration::from_secs(1)).await;

        // Switch back to `first` in a single reorg: disconnecting `sibling` evicts the
        // transaction, and connecting `first` confirms it again before the driver rebroadcasts.
        info!(%first, %sibling, "reorging from the sibling back onto the first block");
        bitcoind
            .client
            .call::<()>("reconsiderblock", &[first.to_string().into()])?;
        bitcoind
            .client
            .call::<()>("preciousblock", &[first.to_string().into()])?;
        assert_eq!(bitcoind.client.get_best_block_hash()?.block_hash()?, first);
        let first_block = bitcoind.client.get_block(first)?;
        assert!(first_block
            .txdata
            .iter()
            .any(|tx| tx.compute_txid() == child.compute_txid()));
        tokio::time::sleep(Duration::from_secs(1)).await;

        for _ in 0..(crate::constants::DEFAULT_BURY_DEPTH + 2) {
            bitcoind.client.generate_to_address(1, &new_address)?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    };

    tokio::time::timeout(
        Duration::from_secs(90),
        futures::future::try_join(drive_to_buried, reorg_then_bury),
    )
    .await
    .expect("drive must resolve after the sibling reorg")?;

    Ok(())
}
