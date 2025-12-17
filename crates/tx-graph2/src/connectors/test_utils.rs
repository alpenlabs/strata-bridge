//! Utilities to test connectors.

use std::collections::VecDeque;

use bitcoin::{
    absolute, consensus, relative,
    sighash::{Prevouts, SighashCache},
    transaction, Address, Amount, BlockHash, OutPoint, Psbt, Transaction, TxOut, Txid,
};
use bitcoind_async_client::types::SignRawTransactionWithWallet;
use corepc_node::{serde_json::json, Client, Conf, Node};
use secp256k1::Message;
use strata_bridge_common::logging::{self, LoggerConfig};
use strata_bridge_primitives::scripts::prelude::create_tx_ins;
use tracing::info;

use crate::connectors::Connector;

/// Generator of witness data for a given [`Connector`].
pub(crate) trait Signer: Sized {
    /// Connector of the signer.
    type Connector: Connector;

    // TODO: (@uncomputable) Replace with arbitrary::Arbitrary
    /// Generates a random signer instance.
    fn generate() -> Self;

    /// Generates the connector that corresponds to the signer.
    fn get_connector(&self) -> Self::Connector;

    /// Returns the name of the connector.
    fn get_connector_name(&self) -> &'static str;

    /// Returns the relative timelock for the given `leaf_index`,
    /// if there is a timelock.
    fn get_relative_timelock(&self, _leaf_index: usize) -> Option<relative::LockTime> {
        None
    }

    /// Generates a witness for the given `leaf_index` using the provided `sighash`.
    ///
    /// # Warning
    ///
    /// The `sighash` has to be computed based on the chosen key-path or script-path spend.
    fn sign_leaf(
        &self,
        leaf_index: Option<usize>,
        sighash: Message,
    ) -> <Self::Connector as Connector>::Witness;

    /// Asserts that the connector is spendable at the given `leaf_index`.
    ///
    /// A random signer is generated using [`Signer::generate`].
    /// The signer generates the connector and a witness automatically.
    /// Bitcoin Core is used to check transaction validity.
    fn assert_connector_is_spendable(leaf_index: Option<usize>) {
        let signer = Self::generate();

        logging::init(LoggerConfig::new(format!(
            "{}-connector",
            signer.get_connector_name()
        )));

        let connector = signer.get_connector();
        let mut node = BitcoinNode::new();
        let fee = Amount::from_sat(1_000);

        // Create a transaction that funds the connector.
        //
        // inputs        | outputs
        // --------------+------------------------
        // N sat: wallet | M sat: connector
        //               |------------------------
        //               | N - M - fee sat: wallet
        let input = create_tx_ins([node.next_coinbase_outpoint()]);
        let output = vec![
            connector.tx_out(),
            TxOut {
                value: node.coinbase_amount() - connector.value() - fee,
                script_pubkey: node.wallet_address().script_pubkey(),
            },
        ];
        let funding_tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        let funding_txid = node.sign_and_broadcast(&funding_tx);
        info!(%funding_txid, "Funding transaction was broadcasted");
        node.mine_blocks(10);

        // Create a transaction that spends the connector.
        //
        // inputs           | outputs
        // -----------------+------------------------
        // M sat: connector | N + M - fee sat: wallet
        // -----------------|
        // N sat: wallet    |
        let input = create_tx_ins([
            OutPoint {
                txid: funding_txid,
                vout: 0,
            },
            node.next_coinbase_outpoint(),
        ]);
        let output = vec![TxOut {
            value: node.coinbase_amount() + connector.value() - fee,
            script_pubkey: node.wallet_address().script_pubkey(),
        }];
        let mut spending_tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        // Update the sequence number
        // This influences the sighash!
        if let Some(timelock) = leaf_index.and_then(|i| signer.get_relative_timelock(i)) {
            spending_tx.input[0].sequence = timelock.to_sequence();
        }

        // Sign the spending transaction
        let utxos = [connector.tx_out(), node.coinbase_tx_out()];
        let mut cache = SighashCache::new(&spending_tx);
        let prevouts = Prevouts::All(&utxos);
        let input_index = 0;
        let sighash = connector.compute_sighash(leaf_index, &mut cache, prevouts, input_index);
        let witness = signer.sign_leaf(leaf_index, sighash);

        let mut psbt = Psbt::from_unsigned_tx(spending_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(connector.tx_out());
        psbt.inputs[1].witness_utxo = Some(node.coinbase_tx_out());
        connector.finalize_input(&mut psbt.inputs[0], &witness);
        info!(%funding_txid, "Spending transaction was signed");

        let spending_tx = psbt.extract_tx().expect("should be able to extract tx");
        let _ = node.sign_and_broadcast(&spending_tx);
    }
}

/// Bitcoin Core node in regtest mode.
#[derive(Debug)]
pub(crate) struct BitcoinNode {
    node: Node,
    wallet_address: Address,
    coinbase_txids: VecDeque<Txid>,
}

impl Default for BitcoinNode {
    fn default() -> Self {
        Self::new()
    }
}

impl BitcoinNode {
    // TODO: (@uncomputable) Pass Option<Conf> argument?
    /// Creates a new bitcoin node.
    ///
    /// 200 blocks are mined, so the coinbases of blocks 0..100 become mature.
    /// These coinbases are owned by the wallet and can be used to fund transaction inputs.
    // NOTE: (@uncomputable) 100 spendable coinbase outputs should be enough for most unit tests.
    //                       Tests that run out of coinbases can mine more blocks.
    pub(crate) fn new() -> Self {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let bitcoind = Node::with_conf("bitcoind", &conf).unwrap();
        let client = &bitcoind.client;

        let mut node = Self {
            wallet_address: client.new_address().unwrap(),
            node: bitcoind,
            coinbase_txids: VecDeque::new(),
        };
        node.mine_blocks(200);
        node
    }

    /// Accesses the bitcoin client.
    pub(crate) fn client(&self) -> &Client {
        &self.node.client
    }

    /// Returns the coinbase amount for blocks of the first halving epoch.
    pub(crate) const fn coinbase_amount(&self) -> Amount {
        Amount::from_sat(50 * 100_000_000)
    }

    /// Accesses the wallet address.
    ///
    /// The node can automatically sign inputs that spend from this address.
    pub(crate) fn wallet_address(&self) -> &Address {
        &self.wallet_address
    }

    /// Returns the outpoint of a fresh coinbase transaction.
    ///
    /// This method implements an iterator,
    /// so it returns a fresh coinbase outpoint on each call.
    ///
    /// The order of coinbase transactions does not follow the block height.
    /// Assume an arbitrary order.
    ///
    /// # Panics
    ///
    /// This method panics if there are no more coinbases.
    /// In this case, you have to mine more blocks.
    pub(crate) fn next_coinbase_outpoint(&mut self) -> OutPoint {
        OutPoint {
            txid: self.coinbase_txids.pop_front().expect("no more coinbases"),
            vout: 0,
        }
    }

    /// Returns the transaction output of any coinbase transaction.
    ///
    /// This node sends coinbase funds always to the wallet address,
    /// so the coinbase output is the same regardless of block height.
    /// regardless of block height.
    pub(crate) fn coinbase_tx_out(&self) -> TxOut {
        TxOut {
            value: self.coinbase_amount(),
            script_pubkey: self.wallet_address.script_pubkey(),
        }
    }

    /// Mines the given number of blocks.
    ///
    /// Funds go to the wallet address.
    pub(crate) fn mine_blocks(&mut self, n_blocks: usize) {
        let coinbase_txids: Vec<Txid> = self
            .client()
            .generate_to_address(n_blocks, self.wallet_address())
            .expect("must be able to generate blocks")
            .0
            .into_iter()
            .map(|block_hash| block_hash.parse::<BlockHash>().expect("must parse"))
            .map(|block_hash| {
                self.client()
                    .get_block(block_hash)
                    .expect("must be able to get coinbase block")
                    .coinbase()
                    .expect("must be able to get the coinbase transaction")
                    .compute_txid()
            })
            .collect();
        self.coinbase_txids.extend(coinbase_txids);
    }

    /// Signs the inputs that the wallet controls and returns the resulting transaction.
    pub(crate) fn sign(&self, partially_signed_tx: &Transaction) -> Transaction {
        let signed_tx = self
            .client()
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(consensus::encode::serialize_hex(
                    &partially_signed_tx
                ))],
            )
            .expect("should be able to sign the transaction inputs");
        consensus::encode::deserialize_hex(&signed_tx.hex).expect("must deserialize")
    }

    /// Signs the inputs that the wallet controls and broadcasts the transaction.
    ///
    /// # Panics
    ///
    /// This method panics if the transaction is not accepted by the mempool.
    pub(crate) fn sign_and_broadcast(&self, partially_signed_tx: &Transaction) -> Txid {
        let signed_tx = self.sign(partially_signed_tx);
        self.client()
            .send_raw_transaction(&signed_tx)
            .unwrap()
            .txid()
            .expect("should be able to extract the txid")
    }

    /// Submits a package of transactions to the mempool.
    ///
    /// # Panics
    ///
    /// This method panics if the package is not accepted by the mempool.
    pub(crate) fn submit_package(&self, transactions: [Transaction; 2]) {
        let result = self
            .client()
            .submit_package(&transactions, None, None)
            .expect("should be able to submit package");
        assert!(
            result.package_msg == "success",
            "Package submission failed. Is the package invalid?"
        );
        assert!(
            result.tx_results.len() == 2,
            "tx_results should have 2 elements"
        );
    }
}
