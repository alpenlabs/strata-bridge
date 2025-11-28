//! Connector for adding an output to a transaction for CPFP.
//!
//! Reference: <https://bitcoinops.org/en/topics/cpfp/>

use bitcoin::{psbt::Input, Network, ScriptBuf};
use bitcoin_bosd::{Descriptor, DescriptorError};
use secp256k1::schnorr;
use strata_bridge_primitives::scripts::taproot::finalize_input;

/// Connector for adding outputs to a transaction for CPFP.
///
/// It creates a taproot locking script with a public key that is assumed to be tweaked and expects
/// a schnorr signature to finalize the input.
#[derive(Debug, Clone)]
pub struct ConnectorCpfp {
    /// The bitcoin network for which to generate output addresses.
    network: Network,

    /// The locking script for the child transaction in CPFP.
    locking_script: ScriptBuf,
}

impl ConnectorCpfp {
    /// Constructs a new CPFP connector.
    ///
    /// # Errors
    ///
    /// Returns an error if the descriptor cannot be converted to an address.
    pub fn new(descriptor: Descriptor, network: Network) -> Result<Self, DescriptorError> {
        let locking_script = descriptor.to_address(network)?.script_pubkey();
        Ok(Self {
            network,
            locking_script,
        })
    }

    /// Returns the bitcoin network for which to generate output addresses.
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Generates the locking script for the child transaction.
    pub fn locking_script(&self) -> ScriptBuf {
        self.locking_script.clone()
    }

    /// Finalizes the connector using a schnorr signature.
    pub fn finalize_input(&self, input: &mut Input, signature: schnorr::Signature) {
        let witnesses = [signature.serialize()];

        finalize_input(input, witnesses);
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{
        consensus,
        hashes::Hash,
        key::TapTweak,
        sighash::{Prevouts, SighashCache},
        transaction::Version,
        Address, Amount, OutPoint, Psbt, TapSighashType, Transaction, TxOut,
    };
    use bitcoind_async_client::types::{ListUnspent, SignRawTransactionWithWallet};
    use corepc_node::{serde_json::json, Conf, Node};
    use secp256k1::{Message, SECP256K1};
    use strata_bridge_common::logging::{self, LoggerConfig};
    use strata_bridge_primitives::scripts::prelude::{create_tx, create_tx_ins, create_tx_outs};
    use strata_bridge_test_utils::{prelude::generate_keypair, tx::FEES};

    use super::*;

    #[test]
    fn test_connector_cpfp() {
        logging::init(LoggerConfig::new("cpfp-test".to_string()));

        let mut conf = Conf::default();
        conf.args.push("-txindex=1");

        let bitcoind = Node::with_conf("bitcoind", &conf).expect("must be able to start bitcoind");
        let btc_client = &bitcoind.client;

        let wallet_addr = btc_client
            .new_address()
            .expect("must be able to get new address");
        btc_client
            .generate_to_address(101, &wallet_addr)
            .expect("must be able to generate to address");

        let network = btc_client
            .get_blockchain_info()
            .expect("must get blockchain info")
            .chain;
        let network = Network::from_str(&network).expect("network must be valid");

        let keypair = generate_keypair();
        let xonly_pubkey = keypair.x_only_public_key().0;
        let connector =
            ConnectorCpfp::new(xonly_pubkey.into(), network).expect("must create connector");

        let output_address =
            Address::p2tr_tweaked(xonly_pubkey.dangerous_assume_tweaked(), network);

        let unspent = btc_client
            .call::<Vec<ListUnspent>>("listunspent", &[])
            .expect("must be able to get utxos")
            .into_iter()
            .find(|utxo| utxo.amount > FEES)
            .expect("must have at least one utxo");

        let utxo = OutPoint {
            txid: unspent.txid,
            vout: unspent.vout,
        };

        // First, create a transaction that creates a UTXO with dust value.
        let starting_tx_ins = create_tx_ins([utxo]);
        let starting_tx_outs = create_tx_outs([
            (
                connector.locking_script(),
                Amount::from_sat(0), // set amount later
            ),
            (wallet_addr.script_pubkey(), unspent.amount),
        ]);
        let mut starting_tx = create_tx(starting_tx_ins, starting_tx_outs);

        // TRUC policy does not allow outputs less than the dust amount.
        let dust_amount = Amount::from_sat(500);

        starting_tx.output[0].value = dust_amount;
        starting_tx.output[1].value = unspent.amount - starting_tx.output[0].value - FEES;

        let signed_starting_tx = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(consensus::encode::serialize_hex(&starting_tx))],
            )
            .expect("must be able to sign raw transaction");

        let signed_starting_tx =
            consensus::encode::deserialize_hex::<Transaction>(&signed_starting_tx.hex)
                .expect("must be able to deserialize signed transaction");
        btc_client
            .send_raw_transaction(&signed_starting_tx)
            .expect("must be able to send raw transaction");

        btc_client
            .generate_to_address(6, &wallet_addr)
            .expect("must be able to mine blocks");

        // Then use the dust-value UTXO to create a parent transaction that also has a dust value.
        let input_utxo_vout = signed_starting_tx
            .output
            .iter()
            .position(|out| out.value == dust_amount)
            .expect("must have a dust output");
        let input_utxo = OutPoint {
            txid: signed_starting_tx.compute_txid(),
            vout: input_utxo_vout as u32,
        };

        let parent_tx_ins = create_tx_ins([input_utxo]);
        let parent_tx_outs = vec![TxOut {
            value: signed_starting_tx.output[input_utxo_vout].value, /* same output as input (0
                                                                      * fees) */
            script_pubkey: connector.locking_script(),
        }];
        let mut parent_tx = create_tx(parent_tx_ins, parent_tx_outs);
        parent_tx.version = Version(3);

        let mut sighasher = SighashCache::new(&mut parent_tx);
        let prevouts = [TxOut {
            value: signed_starting_tx.output[input_utxo_vout].value,
            script_pubkey: signed_starting_tx.output[input_utxo_vout]
                .script_pubkey
                .clone(),
        }];
        let prevouts = Prevouts::All(&prevouts);
        let parent_tx_sighash = sighasher
            .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
            .expect("must be able to create a message hash for parent tx");
        let parent_tx_msg = Message::from_digest_slice(parent_tx_sighash.as_byte_array())
            .expect("must be valid message");

        let parent_signature = SECP256K1.sign_schnorr(&parent_tx_msg, &keypair);

        sighasher
            .witness_mut(0)
            .unwrap()
            .push(parent_signature.serialize());
        let signed_parent_tx = sighasher.into_transaction();

        // Finally, the child transaction that spends the parent transaction as well as
        // another UTXO that pays the fees.
        let unspent = btc_client
            .call::<Vec<ListUnspent>>("listunspent", &[])
            .expect("must be able to get utxos")
            .into_iter()
            .find(|utxo| utxo.amount > FEES)
            .expect("must have at least one utxo");
        let utxo = OutPoint {
            txid: unspent.txid,
            vout: unspent.vout,
        };

        let funding_tx_ins = create_tx_ins([utxo]);
        let funding_tx_outs = create_tx_outs([
            (connector.locking_script(), FEES),
            (wallet_addr.script_pubkey(), unspent.amount - FEES - FEES),
        ]);
        let funding_tx = create_tx(funding_tx_ins, funding_tx_outs);

        let signed_funding_tx = btc_client
            .call::<SignRawTransactionWithWallet>(
                "signrawtransactionwithwallet",
                &[json!(consensus::encode::serialize_hex(&funding_tx))],
            )
            .expect("must be able to sign raw transaction");
        let signed_funding_tx =
            consensus::encode::deserialize_hex::<Transaction>(&signed_funding_tx.hex)
                .expect("must be able to deserialize signed transaction");

        btc_client
            .send_raw_transaction(&signed_funding_tx)
            .expect("must be able to send tx");
        btc_client
            .generate_to_address(6, &wallet_addr)
            .expect("must be able to mine blocks");

        let child_tx_ins = create_tx_ins([
            OutPoint {
                txid: signed_parent_tx.compute_txid(),
                vout: 0,
            },
            OutPoint {
                txid: signed_funding_tx.compute_txid(),
                vout: 0,
            },
        ]);
        let child_tx_outs =
            create_tx_outs([(output_address.script_pubkey(), starting_tx.output[0].value)]);
        let mut child_tx = create_tx(child_tx_ins, child_tx_outs);
        child_tx.version = Version(3);

        let mut psbt = Psbt::from_unsigned_tx(child_tx.clone()).expect("must be unsigned");
        let mut sighasher = SighashCache::new(&mut child_tx);

        let prevouts = [
            TxOut {
                value: signed_parent_tx.output[0].value,
                script_pubkey: signed_parent_tx.output[0].script_pubkey.clone(),
            },
            TxOut {
                value: funding_tx.output[0].value,
                script_pubkey: funding_tx.output[0].script_pubkey.clone(),
            },
        ];
        psbt.inputs[0].witness_utxo = Some(prevouts[0].clone());
        psbt.inputs[1].witness_utxo = Some(prevouts[1].clone());
        let prevouts = Prevouts::All(&prevouts);

        let child_tx_hash = sighasher
            .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
            .expect("must be able to create a message hash for CPFP input");
        let child_tx_msg = Message::from_digest_slice(child_tx_hash.as_byte_array())
            .expect("must be valid message");

        let child_signature = SECP256K1.sign_schnorr(&child_tx_msg, &keypair);
        connector.finalize_input(&mut psbt.inputs[0], child_signature);

        let funding_tx_hash = sighasher
            .taproot_key_spend_signature_hash(1, &prevouts, TapSighashType::Default)
            .expect("must be able to create a message hash for CPFP input");
        let funding_tx_msg = Message::from_digest_slice(funding_tx_hash.as_byte_array())
            .expect("must be valid message");
        let funding_signature = SECP256K1.sign_schnorr(&funding_tx_msg, &keypair);

        finalize_input(&mut psbt.inputs[1], [funding_signature.serialize()]);
        let signed_child_tx = psbt
            .extract_tx()
            .expect("must be able to extract signed tx from psbt");

        // confirm all pending transactions before submitting package.
        btc_client
            .generate_to_address(6, &wallet_addr)
            .expect("must be able to generate to address");

        let parent_txid = signed_parent_tx.compute_txid();
        let result = btc_client
            .submit_package(
                &[signed_parent_tx.clone(), signed_child_tx.clone()],
                None,
                None,
            )
            .expect("must be able to submit 1P1C package");

        assert_eq!(
            result.package_msg, "success",
            "must be able to submit 1P1C package successfully"
        );
        assert!(result.tx_results.len() == 2, "must have 2 tx results");

        btc_client
            .generate_to_address(6, &wallet_addr)
            .expect("must be able to mine blocks");

        btc_client
            .call::<String>("getrawtransaction", &[json!(parent_txid)])
            .expect("must find parent tx on chain");
    }
}
