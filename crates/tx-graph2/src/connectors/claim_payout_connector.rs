//! This module contains the claim payout connector.

use bitcoin::{
    hashes::{sha256, Hash},
    opcodes,
    psbt::Input,
    taproot::{LeafVersion, TaprootSpendInfo},
    Network, ScriptBuf, TxOut,
};
use secp256k1::{schnorr, XOnlyPublicKey};
use strata_bridge_primitives::scripts::prelude::{create_taproot_addr, finalize_input, SpendPath};

/// Connector output between `Claim` and the payouts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClaimPayoutConnector {
    network: Network,
    n_of_n_pubkey: XOnlyPublicKey,
    admin_pubkey: XOnlyPublicKey,
    unstaking_image: sha256::Hash,
}

impl ClaimPayoutConnector {
    /// Creates a new connector.
    pub const fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        admin_pubkey: XOnlyPublicKey,
        unstaking_image: sha256::Hash,
    ) -> Self {
        Self {
            network,
            n_of_n_pubkey,
            admin_pubkey,
            unstaking_image,
        }
    }

    /// Generates a vector of all leaf scripts of the connector.
    pub fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        let mut scripts = Vec::new();

        let admin_burn_script = ScriptBuf::builder()
            .push_slice(self.admin_pubkey.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script();
        scripts.push(admin_burn_script);

        let unstaking_burn_script = ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_SIZE)
            .push_int(0x20)
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_SHA256)
            .push_slice(self.unstaking_image.to_byte_array())
            .push_opcode(opcodes::all::OP_EQUAL)
            .into_script();
        scripts.push(unstaking_burn_script);

        scripts
    }

    /// Generates the bitcoin address and taproot spending info of the connector.
    pub fn address_and_spend_info(&self) -> (bitcoin::Address, TaprootSpendInfo) {
        let internal_key = self.n_of_n_pubkey;
        let scripts = self.leaf_scripts();
        create_taproot_addr(
            &self.network,
            SpendPath::Both {
                internal_key,
                scripts: scripts.as_slice(),
            },
        )
        .expect("tap tree is valid")
    }

    /// Generates the txout of the connector.
    pub fn tx_out(&self) -> TxOut {
        let script_pubkey = self.address_and_spend_info().0.script_pubkey();
        let minimal_non_dust = script_pubkey.minimal_non_dust();

        TxOut {
            value: minimal_non_dust,
            script_pubkey,
        }
    }

    /// Finalizes the PSBT `input` where the connector is used, using the provided `witness`.
    pub fn finalize_input(&self, input: &mut Input, witness: ClaimPayoutWitness) {
        let (leaf_index, leaf_script_input) = match &witness {
            ClaimPayoutWitness::Payout {
                output_key_signature: n_of_n_signature,
            } => {
                finalize_input(input, [n_of_n_signature.serialize().to_vec()]);
                return;
            }
            ClaimPayoutWitness::AdminBurn { admin_signature } => {
                (0, admin_signature.serialize().to_vec())
            }
            ClaimPayoutWitness::UnstakingBurn { unstaking_preimage } => {
                (1, unstaking_preimage.to_vec())
            }
        };

        let leaf_script = self.leaf_scripts().remove(leaf_index);
        let script_ver = (leaf_script, LeafVersion::TapScript);
        let taproot_spend_info = self.address_and_spend_info().1;
        let control_block = taproot_spend_info
            .control_block(&script_ver)
            .expect("leaf script exists");
        let leaf_script = script_ver.0;

        let witness = [
            leaf_script_input,
            leaf_script.to_bytes(),
            control_block.serialize(),
        ];
        finalize_input(input, witness);
    }
}

/// Witness data to spend a [`ClaimPayoutConnector`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ClaimPayoutWitness {
    /// The connector is spent in a payout transaction.
    Payout {
        /// Output key signature (key-path spend).
        ///
        /// The output key is the N/N key tweaked with the tap tree merkle root.
        output_key_signature: schnorr::Signature,
    },
    /// The connector is spent in the admin burn transaction.
    AdminBurn {
        /// Admin signature.
        admin_signature: schnorr::Signature,
    },
    /// The connector is spent in the unstaking burn transaction.
    UnstakingBurn {
        /// Preimage that is revealed when the operator posts the unstaking intent transaction.
        unstaking_preimage: [u8; 32],
    },
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute, consensus,
        key::TapTweak,
        sighash::{Prevouts, SighashCache},
        transaction, Amount, BlockHash, OutPoint, Psbt, TapSighashType, Transaction, TxIn, TxOut,
    };
    use bitcoind_async_client::types::SignRawTransactionWithWallet;
    use corepc_node::{serde_json::json, Conf, Node};
    use secp256k1::{rand::random, Keypair, Message, SECP256K1};
    use strata_bridge_common::logging::{self, LoggerConfig};
    use strata_bridge_primitives::scripts::taproot::{
        create_key_spend_hash, create_script_spend_hash,
    };
    use strata_bridge_test_utils::prelude::generate_keypair;
    use tracing::info;

    use super::*;

    struct Signer {
        n_of_n_keypair: Keypair,
        admin_keypair: Keypair,
        unstaking_preimage: [u8; 32],
    }

    impl Signer {
        fn generate() -> Self {
            Self {
                n_of_n_keypair: generate_keypair(),
                admin_keypair: generate_keypair(),
                unstaking_preimage: random::<[u8; 32]>(),
            }
        }

        fn get_connector(&self) -> ClaimPayoutConnector {
            ClaimPayoutConnector::new(
                Network::Regtest,
                self.n_of_n_keypair.x_only_public_key().0,
                self.admin_keypair.x_only_public_key().0,
                sha256::Hash::hash(&self.unstaking_preimage),
            )
        }

        fn sign_leaf(&self, leaf_index: Option<usize>, sighash: Message) -> ClaimPayoutWitness {
            match leaf_index {
                None => {
                    let connector = self.get_connector();
                    let merkle_root = connector.address_and_spend_info().1.merkle_root();
                    let output_keypair = self
                        .n_of_n_keypair
                        .tap_tweak(SECP256K1, merkle_root)
                        .to_keypair();
                    ClaimPayoutWitness::Payout {
                        output_key_signature: output_keypair.sign_schnorr(sighash),
                    }
                }
                Some(0) => ClaimPayoutWitness::AdminBurn {
                    admin_signature: self.admin_keypair.sign_schnorr(sighash),
                },
                Some(1) => ClaimPayoutWitness::UnstakingBurn {
                    unstaking_preimage: self.unstaking_preimage,
                },
                _ => panic!("Invalid tap leaf"),
            }
        }
    }

    fn spend_connector(connector: ClaimPayoutConnector, signer: Signer, leaf_index: Option<usize>) {
        logging::init(LoggerConfig::new("claim-payout-connector".to_string()));

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
                script_pubkey: connector.tx_out().script_pubkey,
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

        let spending_tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spending_input,
                ..Default::default()
            }],
            output: vec![spending_output],
        };

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
            script_pubkey: connector.tx_out().script_pubkey,
        });

        let witness = signer.sign_leaf(leaf_index, sighash);
        connector.finalize_input(&mut psbt.inputs[0], witness);
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

    #[test]
    fn payout_spend() {
        let signer = Signer::generate();
        let connector = signer.get_connector();
        spend_connector(connector, signer, None);
    }

    #[test]
    fn admin_burn_spend() {
        let signer = Signer::generate();
        let connector = signer.get_connector();
        spend_connector(connector, signer, Some(0));
    }

    #[test]
    fn unstaking_burn_spend() {
        let signer = Signer::generate();
        let connector = signer.get_connector();
        spend_connector(connector, signer, Some(1));
    }
}
