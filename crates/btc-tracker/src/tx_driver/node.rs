//! The driver's access to the node: ZMQ subscriptions, and RPC reads and broadcasts.

use async_trait::async_trait;
use bitcoin::{Amount, BlockHash, OutPoint, Transaction, Txid};
use bitcoind_async_client::{
    error::ClientError,
    traits::{Broadcaster, Reader},
    types::BroadcastOptions,
    Client as BitcoinClient,
};
use strata_bridge_primitives::subscription::Subscription;

use crate::{
    client::{BtcNotifyClient, Connected},
    event::{TxEvent, TxStatus},
};

fn broadcast_options(tx: &Transaction) -> Option<BroadcastOptions> {
    let max_burn_amount = tx
        .output
        .iter()
        .filter(|output| output.value > Amount::ZERO && output.script_pubkey.is_op_return())
        .map(|output| output.value)
        .max()?;

    Some(BroadcastOptions {
        max_burn_amount: Some(max_burn_amount),
        ..Default::default()
    })
}

/// The predicate of a transaction subscription.
///
/// The filter compares txids, not witnesses. The driver tracks whether a transaction reaches the
/// chain, not which spend path its witness takes, so a variant with another witness counts as the
/// same transaction.
fn matches_txid(tx: &Transaction) -> impl Fn(&Transaction) -> bool + Send + Sync + 'static {
    let txid = tx.compute_txid();
    let first_input = first_prevout(tx);
    // `BtcNotifyClient` runs every subscription's filter on every transaction it sees, in the
    // mempool and in each block, so this closure is on a hot path. Computing a candidate's txid
    // means a double SHA-256 over its serialization. Comparing first prevouts is a plain
    // comparison of outpoints, and it rejects nearly every other transaction before that hash
    // runs.
    //
    // The prevout check never rejects a match: the first prevout is part of the data the txid
    // commits to, so two transactions with equal txids spend the same first prevout.
    move |candidate| first_prevout(candidate) == first_input && candidate.compute_txid() == txid
}

/// The outpoint that the first input of `tx` spends.
fn first_prevout(tx: &Transaction) -> Option<OutPoint> {
    tx.input.first().map(|input| input.previous_output)
}

/// The status of a transaction in a block of the active chain.
///
/// `confirmations` counts the containing block, and `bury_depth` counts the blocks built on top of
/// it, as the client's state machine does. A transaction with more than `bury_depth` confirmations
/// reads as buried.
pub(super) const fn confirmed_status(
    confirmations: u64,
    blockhash: BlockHash,
    height: u64,
    bury_depth: u64,
) -> TxStatus {
    if confirmations > bury_depth {
        TxStatus::Buried { blockhash, height }
    } else {
        TxStatus::Mined { blockhash, height }
    }
}

/// Node access of the driver loop.
///
/// Everything that touches the node sits behind this trait, so that a test double can stand in
/// for the node. The production implementation is [`NodeAccess`].
#[async_trait]
pub(super) trait ChainAccess: Send + Sync {
    /// Opens the ZMQ subscription of `tx`.
    async fn subscribe(&self, tx: &Transaction) -> Subscription<TxEvent>;

    /// Reads the status of `txid`. A transaction that the node does not know reads as
    /// [`TxStatus::Unknown`]. An RPC failure is an error, so that a caller does not mistake a
    /// transport fault for an eviction.
    async fn fetch_status(&self, txid: Txid) -> Result<TxStatus, ClientError>;

    /// Sends `tx` to the mempool without a package.
    async fn broadcast(&self, tx: &Transaction) -> Result<Txid, ClientError>;
}

/// The [`ChainAccess`] of a live node: ZMQ for subscriptions and RPC for everything else.
pub(super) struct NodeAccess {
    pub(super) zmq_client: BtcNotifyClient<Connected>,
    pub(super) rpc_client: BitcoinClient,
}

/// Reads the status of `txid` through `getrawtransaction`. The result covers confirmed
/// transactions only when the node runs with `txindex=1`.
///
/// A transaction with no confirmations reads as in the mempool. `txindex` also keeps a
/// transaction of a block that a reorg removed, with a block hash and zero confirmations, and it
/// reads the same way. A confirmed transaction with no block hash is a malformed answer, and it
/// reads as in the mempool too, so that the driver does not stop.
pub(super) async fn read_status(
    rpc_client: &BitcoinClient,
    txid: Txid,
    bury_depth: u64,
) -> Result<TxStatus, ClientError> {
    let tx_data = match rpc_client.get_raw_transaction_verbosity_one(&txid).await {
        Ok(tx_data) => tx_data,
        Err(err) if err.is_tx_not_found() => return Ok(TxStatus::Unknown),
        Err(err) => return Err(err),
    };
    match (tx_data.confirmations.unwrap_or(0), tx_data.block_hash) {
        (0, _) | (_, None) => Ok(TxStatus::Mempool),
        (confirmations, Some(blockhash)) => {
            // This uses `0` as the default since a block height of `0` does not satisfy any
            // practical predicate.
            let height = rpc_client.get_block_height(&blockhash).await.unwrap_or(0);
            Ok(confirmed_status(
                confirmations,
                blockhash,
                height,
                bury_depth,
            ))
        }
    }
}

#[async_trait]
impl ChainAccess for NodeAccess {
    async fn subscribe(&self, tx: &Transaction) -> Subscription<TxEvent> {
        self.zmq_client
            .subscribe_transactions(matches_txid(tx))
            .await
    }

    async fn fetch_status(&self, txid: Txid) -> Result<TxStatus, ClientError> {
        read_status(&self.rpc_client, txid, self.zmq_client.bury_depth() as u64).await
    }

    async fn broadcast(&self, tx: &Transaction) -> Result<Txid, ClientError> {
        self.rpc_client
            .send_raw_transaction(tx, broadcast_options(tx))
            .await
    }
}

#[cfg(test)]
mod filter_tests {
    use bitcoin::{
        absolute, hashes::Hash, transaction, Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut,
        Txid,
    };

    use super::{broadcast_options, matches_txid};

    fn tx_with_outputs(output: Vec<TxOut>) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output,
        }
    }

    /// A transaction that spends one output named by `seed`.
    fn spending(seed: u8) -> Transaction {
        Transaction {
            version: transaction::Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([seed; 32]), 0),
                ..TxIn::default()
            }],
            output: vec![],
        }
    }

    #[test]
    fn the_subscription_filter_matches_another_witness_and_no_other_txid() {
        let tx = spending(1);
        let mut variant = tx.clone();
        variant.input[0].witness.push([1]);
        assert_ne!(tx, variant, "the variant carries another witness");
        let mut same_first_input = tx.clone();
        same_first_input.lock_time = absolute::LockTime::from_consensus(1);

        let filter = matches_txid(&tx);

        assert!(
            filter(&variant),
            "another witness of the transaction matches"
        );
        assert!(
            !filter(&spending(2)),
            "a transaction of another input does not match"
        );
        assert!(
            !filter(&same_first_input),
            "another txid with the same first input does not match"
        );
    }

    #[test]
    fn broadcast_options_use_largest_op_return_burn() {
        let tx = tx_with_outputs(vec![
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_op_return([1u8; 32]),
            },
            TxOut {
                value: Amount::from_sat(2_000),
                script_pubkey: ScriptBuf::new_op_return([2u8; 32]),
            },
            TxOut {
                value: Amount::from_sat(3_000),
                script_pubkey: ScriptBuf::new(),
            },
        ]);

        let options = broadcast_options(&tx).expect("OP_RETURN burn must require options");

        assert_eq!(options.max_burn_amount, Some(Amount::from_sat(2_000)));
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;

    use super::*;

    /// `bury_depth` counts the blocks built on top, as the client's state machine does, so a
    /// transaction is buried once it has more confirmations than that.
    #[test]
    fn confirmed_status_buries_past_the_bury_depth() {
        let blockhash = BlockHash::all_zeros();
        let mined = TxStatus::Mined {
            blockhash,
            height: 100,
        };
        let buried = TxStatus::Buried {
            blockhash,
            height: 100,
        };

        assert_eq!(
            confirmed_status(1, blockhash, 100, 6),
            mined,
            "one confirmation is mined"
        );
        assert_eq!(
            confirmed_status(6, blockhash, 100, 6),
            mined,
            "five blocks on top are short of a bury depth of six"
        );
        assert_eq!(
            confirmed_status(7, blockhash, 100, 6),
            buried,
            "six blocks on top bury the transaction"
        );
        assert_eq!(
            confirmed_status(1, blockhash, 100, 0),
            buried,
            "a bury depth of zero buries a block when it connects"
        );
    }
}

/// Tests of the RPC reads against a regtest node. These need no ZMQ, so they run in parallel.
#[cfg(test)]
mod rpc_tests {
    use bitcoin::{Address, Amount};
    use corepc_node::{Conf, Node};

    use super::*;

    fn setup() -> (Node, BitcoinClient, Address) {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let node = Node::with_conf("bitcoind", &conf).expect("bitcoind must start");
        let cookie = node
            .params
            .get_cookie_values()
            .expect("can read cookie")
            .expect("can parse cookie");
        let auth = bitcoind_async_client::Auth::UserPass(cookie.user, cookie.password);
        let client = BitcoinClient::new(node.rpc_url(), auth, None, None, None)
            .expect("can set up rpc client");
        let address = node.client.new_address().expect("wallet address");
        node.client
            .generate_to_address(101, &address)
            .expect("coinbase matures");
        (node, client, address)
    }

    /// Sends one payment and returns the outpoint of the first output of the mempool transaction.
    fn send(node: &Node, address: &Address) -> OutPoint {
        let txid = node
            .client
            .send_to_address(address, Amount::from_btc(1.0).expect("valid amount"))
            .expect("the wallet is funded")
            .txid()
            .expect("valid txid");
        OutPoint { txid, vout: 0 }
    }

    /// `txindex` keeps the entry of a block that left the chain. A transaction in that block reads
    /// as in the mempool, also once a replacement has taken its place there.
    #[tokio::test]
    async fn a_transaction_of_a_disconnected_block_reads_as_in_the_mempool() {
        let (node, client, address) = setup();
        let txid = send(&node, &address).txid;
        let blocks = node
            .client
            .generate_to_address(1, &address)
            .expect("block mines")
            .into_model()
            .expect("valid hashes");
        let block = blocks.0[0].to_string();
        let _: serde::de::IgnoredAny = node
            .client
            .call("invalidateblock", &[block.into()])
            .expect("block disconnects");
        assert_eq!(
            read_status(&client, txid, 2).await.expect("read"),
            TxStatus::Mempool,
            "a disconnect returns the transaction to the mempool"
        );

        let _: serde::de::IgnoredAny = node
            .client
            .call("bumpfee", &[txid.to_string().into()])
            .expect("the replacement takes the mempool");

        assert_eq!(
            read_status(&client, txid, 2).await.expect("read"),
            TxStatus::Mempool,
            "a replaced transaction of a disconnected block still reads as in the mempool"
        );
    }

    #[tokio::test]
    async fn read_status_follows_a_transaction_to_burial() {
        let (node, client, address) = setup();
        let txid = send(&node, &address).txid;
        let unknown = Txid::from_raw_hash(bitcoin::hashes::Hash::all_zeros());

        assert_eq!(
            read_status(&client, unknown, 2).await.expect("read"),
            TxStatus::Unknown,
            "a transaction that the node does not know reads as unknown"
        );
        assert_eq!(
            read_status(&client, txid, 2).await.expect("read"),
            TxStatus::Mempool,
            "a sent transaction reads as in the mempool"
        );

        node.client
            .generate_to_address(1, &address)
            .expect("block mines");
        let status = read_status(&client, txid, 2).await.expect("read");
        assert!(
            status.is_mined(),
            "one confirmation is below the bury depth"
        );
        let height = client.get_block_count().await.expect("tip");
        assert!(
            matches!(status, TxStatus::Mined { height: h, .. } if h == height),
            "the status names the block at the tip, got {status:?}"
        );

        node.client
            .generate_to_address(1, &address)
            .expect("block mines");
        assert!(
            read_status(&client, txid, 2)
                .await
                .expect("read")
                .is_mined(),
            "one block on top is short of a bury depth of two"
        );

        node.client
            .generate_to_address(1, &address)
            .expect("block mines");
        assert!(
            read_status(&client, txid, 2)
                .await
                .expect("read")
                .is_buried(),
            "two blocks on top bury the transaction"
        );
    }
}
