//! Utilities to test connectors.

use std::collections::VecDeque;

use bitcoin::{
    absolute, consensus,
    sighash::{Prevouts, SighashCache},
    transaction, Address, Amount, BlockHash, OutPoint, Psbt, Transaction, TxOut, Txid,
};
use bitcoind_async_client::types::SignRawTransactionWithWallet;
use corepc_node::{
    serde_json::{self, json},
    Client, Conf, Node,
};
use strata_bridge_common::logging::{self, LoggerConfig};
use strata_bridge_primitives::scripts::prelude::create_tx_ins;
use tracing::info;

use crate::{
    connectors::{Connector, SigningInfo},
    transactions::ParentTx,
};

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

    /// Generates a witness for the given `spend_path` using the provided `signing_info`.
    fn sign_leaf(
        &self,
        spend_path: <Self::Connector as Connector>::SpendPath,
        signing_info: SigningInfo,
    ) -> <Self::Connector as Connector>::Witness;

    /// Asserts that the connector is spendable via the given `spend_path`.
    ///
    /// A random signer is generated using [`Signer::generate`].
    /// The signer generates the connector and a witness automatically.
    /// Bitcoin Core is used to check transaction validity.
    fn assert_connector_is_spendable(spend_path: <Self::Connector as Connector>::SpendPath) {
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
        spending_tx.input[0].sequence = connector.sequence(spend_path);

        // Sign the spending transaction
        let utxos = [connector.tx_out(), node.coinbase_tx_out()];
        let mut cache = SighashCache::new(&spending_tx);
        let prevouts = Prevouts::All(&utxos);
        let input_index = 0;
        let signing_info =
            connector.get_signing_info(&mut cache, prevouts, spend_path, input_index);
        let witness = signer.sign_leaf(spend_path, signing_info);

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
    /// 110 blocks are mined, so the coinbases of blocks 0..10 become mature.
    /// These coinbases are owned by the wallet and can be used to fund transaction inputs.
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
        node.mine_blocks(110);
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
        if result.package_msg != "success" {
            dbg!(result);
            panic!("Package submission failed. Is the package invalid?");
        }
        assert!(
            result.tx_results.len() == 2,
            "tx_results should have 2 elements"
        );
    }

    /// Returns a signed transaction that pays fees for the given `parent` via CPFP.
    ///
    /// The `total_fee` covers both the parent and the child.
    pub(crate) fn create_cpfp_child<T: ParentTx>(
        &mut self,
        parent: &T,
        total_fee: Amount,
    ) -> Transaction {
        let input = create_tx_ins([parent.cpfp_outpoint(), self.next_coinbase_outpoint()]);
        let output = vec![TxOut {
            value: self.coinbase_amount() + parent.cpfp_tx_out().value - total_fee,
            script_pubkey: self.wallet_address().script_pubkey(),
        }];
        let child_tx = Transaction {
            version: transaction::Version(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };
        self.sign_with_prevouts(&child_tx, &[parent.cpfp_tx_out()])
    }

    /// Signs the inputs that the wallet controls, providing prevouts for
    /// inputs that spend from unconfirmed transactions.
    fn sign_with_prevouts(
        &self,
        partially_signed_tx: &Transaction,
        prevouts: &[TxOut],
    ) -> Transaction {
        let prevtxs: Vec<serde_json::Value> = partially_signed_tx
            .input
            .iter()
            .zip(prevouts.iter())
            .map(|(input, txout)| {
                json!({
                    "txid": input.previous_output.txid.to_string(),
                    "vout": input.previous_output.vout,
                    "scriptPubKey": txout.script_pubkey.to_hex_string(),
                    "amount": txout.value.to_btc(),
                })
            })
            .collect();

        let signed_tx = self
            .client()
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[
                    json!(consensus::encode::serialize_hex(partially_signed_tx)),
                    json!(prevtxs),
                ],
            )
            .expect("should be able to sign the transaction inputs");
        consensus::encode::deserialize_hex(&signed_tx.hex).expect("must deserialize")
    }
}
