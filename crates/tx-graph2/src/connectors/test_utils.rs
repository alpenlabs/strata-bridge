//! Utilities to test connectors.

use bitcoin::{
    absolute, consensus, relative,
    sighash::{Prevouts, SighashCache},
    transaction, Amount, BlockHash, OutPoint, Psbt, TapSighashType, Transaction, TxIn, TxOut,
};
use bitcoind_async_client::types::SignRawTransactionWithWallet;
use corepc_node::{serde_json::json, Conf, Node};
use strata_bridge_common::logging::{self, LoggerConfig};
use strata_bridge_primitives::scripts::taproot::{create_key_spend_hash, create_script_spend_hash};
use tracing::info;

use crate::connectors::Connector;

/// Generator of witness data for a given [`Connector`].
pub trait Signer: Sized {
    /// Connector of the signer.
    type Connector: Connector;

    // TODO (@uncomputable) Replace with arbitrary::Arbitrary
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
    /// The sighash has to be computed based on the chosen key-path or script-path spend.
    fn sign_leaf(
        &self,
        leaf_index: Option<usize>,
        sighash: secp256k1::Message,
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

        // Setup Bitcoin node
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let bitcoind = Node::with_conf("bitcoind", &conf).unwrap();
        let btc_client = &bitcoind.client;

        // Mine until maturity
        let funded_address = btc_client.new_address().unwrap();
        let change_address = btc_client.new_address().unwrap();
        let coinbase_block = btc_client
            .generate_to_address(101, &funded_address)
            .expect("must be able to generate blocks")
            .0
            .first()
            .expect("must be able to get the blocks")
            .parse::<BlockHash>()
            .expect("must parse");
        let coinbase_txid = btc_client
            .get_block(coinbase_block)
            .expect("must be able to get coinbase block")
            .coinbase()
            .expect("must be able to get the coinbase transaction")
            .compute_txid();

        // Create funding transaction
        let funding_input = OutPoint {
            txid: coinbase_txid,
            vout: 0,
        };

        let coinbase_amount = Amount::from_btc(50.0).expect("must be valid amount");
        let funding_amount = Amount::from_sat(50_000);
        let fees = Amount::from_sat(1_000);

        let input = vec![TxIn {
            previous_output: funding_input,
            ..Default::default()
        }];

        let output = vec![
            TxOut {
                value: funding_amount,
                script_pubkey: connector.script_pubkey(),
            },
            TxOut {
                value: coinbase_amount - funding_amount - fees,
                script_pubkey: change_address.script_pubkey(),
            },
        ];

        let funding_tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        // Sign and broadcast funding transaction
        let signed_funding_tx = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(consensus::encode::serialize_hex(&&funding_tx))],
            )
            .expect("must be able to sign transaction");

        assert!(
            signed_funding_tx.complete,
            "funding transaction should be complete"
        );
        let signed_funding_tx =
            consensus::encode::deserialize_hex(&signed_funding_tx.hex).expect("must deserialize");

        let funding_txid = btc_client
            .send_raw_transaction(&signed_funding_tx)
            .expect("must be able to broadcast transaction")
            .txid()
            .expect("must have txid");

        info!(%funding_txid, "Funding transaction broadcasted");

        // Mine the funding transaction
        let _ = btc_client
            .generate_to_address(10, &funded_address)
            .expect("must be able to generate blocks");

        // Create spending transaction that spends the connector p
        let spending_input = OutPoint {
            txid: funding_txid,
            vout: 0,
        };

        let spending_output = TxOut {
            value: funding_amount - fees,
            script_pubkey: change_address.script_pubkey(),
        };

        let mut spending_tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spending_input,
                ..Default::default()
            }],
            output: vec![spending_output],
        };

        // Update locktime and sequence
        // This influences the sighash!
        if let Some(timelock) = leaf_index.and_then(|i| signer.get_relative_timelock(i)) {
            spending_tx.input[0].sequence = timelock.to_sequence();
        }

        let mut sighash_cache = SighashCache::new(&spending_tx);
        let utxos = [funding_tx.output[0].clone()];
        let prevouts = Prevouts::All(&utxos);
        let sighash_type = TapSighashType::Default;
        let input_index = 0;

        let sighash = if let Some(leaf_index) = leaf_index {
            let leaf_scripts = connector.leaf_scripts();
            create_script_spend_hash(
                &mut sighash_cache,
                &leaf_scripts[leaf_index],
                prevouts,
                sighash_type,
                input_index,
            )
        } else {
            create_key_spend_hash(&mut sighash_cache, prevouts, sighash_type, input_index)
        }
        .expect("should be able to compute sighash");

        // Set the witness in the transaction
        let mut psbt = Psbt::from_unsigned_tx(spending_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: funding_amount,
            script_pubkey: connector.script_pubkey(),
        });

        let witness = signer.sign_leaf(leaf_index, sighash);
        connector.finalize_input(&mut psbt.inputs[0], &witness);
        let spending_tx = psbt.extract_tx().expect("must be signed");

        // Broadcast spending transaction
        let spending_txid = btc_client
            .send_raw_transaction(&spending_tx)
            .expect("must be able to broadcast spending transaction")
            .txid()
            .expect("must have txid");

        info!(%spending_txid, "Spending transaction broadcasted");

        // Verify the transaction was mined
        btc_client
            .generate_to_address(1, &funded_address)
            .expect("must be able to generate block");
    }
}
