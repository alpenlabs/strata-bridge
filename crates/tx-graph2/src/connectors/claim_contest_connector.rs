//! This module contains the connector between `Claim`, `UncontestedPayout`, and `Contest`.

use bitcoin::{
    opcodes,
    psbt::Input,
    relative,
    taproot::{LeafVersion, TaprootSpendInfo},
    Network, ScriptBuf, TxOut,
};
use secp256k1::{schnorr, XOnlyPublicKey};
use strata_bridge_primitives::scripts::prelude::{create_taproot_addr, finalize_input, SpendPath};

/// Connector output between `Claim` and:
/// 1. `UncontestedPayout`, and
/// 2. `Contest`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClaimContestConnector {
    network: Network,
    n_of_n_pubkey: XOnlyPublicKey,
    watchtower_pubkeys: Vec<XOnlyPublicKey>,
    delta_contest: relative::LockTime,
}

impl ClaimContestConnector {
    /// Creates a new connector.
    pub const fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        watchtower_pubkeys: Vec<XOnlyPublicKey>,
        delta_contest: relative::LockTime,
    ) -> Self {
        Self {
            network,
            n_of_n_pubkey,
            watchtower_pubkeys,
            delta_contest,
        }
    }

    /// Returns the number of watchtowers for the connector.
    pub const fn n_watchtowers(&self) -> usize {
        self.watchtower_pubkeys.len()
    }

    /// Returns the delta contest relative timelock of the connector.
    ///
    /// The sequence of the input and the global locktime must be
    /// large enough to cover this value.
    pub const fn delta_contest(&self) -> relative::LockTime {
        self.delta_contest
    }

    /// Generates a vector of all leaf scripts of the connector.
    pub fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        let mut scripts = Vec::new();

        for watchtower_pubkey in &self.watchtower_pubkeys {
            let script = bitcoin::script::Builder::new()
                .push_slice(self.n_of_n_pubkey.serialize())
                .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
                .push_slice(watchtower_pubkey.serialize())
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script();
            scripts.push(script);
        }

        let script = bitcoin::script::Builder::new()
            .push_slice(self.n_of_n_pubkey.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            .push_sequence(self.delta_contest.to_sequence())
            .push_opcode(opcodes::all::OP_CSV)
            .into_script();
        scripts.push(script);

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
        let dust = script_pubkey.minimal_non_dust();
        // TODO: Replace magic number 3 with constant from contest transaction, once the code exists
        let value = dust * (3 * self.n_watchtowers() as u64);

        TxOut {
            value,
            script_pubkey,
        }
    }

    /// Finalizes the PSBT `input` where the connector is used, using the provided `witness`.
    ///
    /// # Warning
    ///
    /// If [`ClaimContestSpendPath::Uncontested`] is used, then the sequence of the transaction
    /// input must be set accordingly. Also, the global locktime has to be set accordingly.
    pub fn finalize_input(&self, input: &mut Input, witness: ClaimContestWitness) {
        let ClaimContestWitness {
            n_of_n_signature,
            spend_path,
        } = witness;
        let taproot_spend_info = self.address_and_spend_info().1;
        let leaf_index = match spend_path {
            ClaimContestSpendPath::Contested {
                watchtower_index,
                watchtower_signature: _,
            } => watchtower_index as usize,
            ClaimContestSpendPath::Uncontested => self.n_watchtowers(),
        };
        let leaf_script = self
            .leaf_scripts()
            .into_iter()
            .nth(leaf_index)
            .expect("leaf script exists");
        let script_ver = (leaf_script, LeafVersion::TapScript);
        let control_block = taproot_spend_info
            .control_block(&script_ver)
            .expect("leaf script exists");
        let leaf_script = script_ver.0;

        match spend_path {
            ClaimContestSpendPath::Contested {
                watchtower_index: _,
                watchtower_signature,
            } => {
                let witness = [
                    watchtower_signature.serialize().to_vec(),
                    n_of_n_signature.serialize().to_vec(),
                    leaf_script.to_bytes(),
                    control_block.serialize(),
                ];
                finalize_input(input, witness);
            }
            ClaimContestSpendPath::Uncontested => {
                let witness = [
                    n_of_n_signature.serialize().to_vec(),
                    leaf_script.to_bytes(),
                    control_block.serialize(),
                ];
                finalize_input(input, witness);
            }
        }
    }
}

/// Witness data to spend a [`ClaimContestConnector`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ClaimContestWitness {
    /// N/N signature of the transaction that spends the connector.
    pub n_of_n_signature: schnorr::Signature,
    /// Used spending path.
    pub spend_path: ClaimContestSpendPath,
}

/// Available spending paths for a [`ClaimContestConnector`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ClaimContestSpendPath {
    /// The connector is spent in the `Contest` transaction.
    Contested {
        /// Index of the spending watchtower.
        watchtower_index: u32,
        /// Signature of the spending watchtower.
        watchtower_signature: schnorr::Signature,
    },
    /// The connector is spent in the `UncontestedPayout` transaction.
    Uncontested,
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use bitcoin::{
        absolute, consensus,
        sighash::{Prevouts, SighashCache},
        transaction, Amount, BlockHash, OutPoint, Psbt, TapSighashType, Transaction, TxIn, TxOut,
    };
    use bitcoind_async_client::types::SignRawTransactionWithWallet;
    use corepc_node::{serde_json::json, Conf, Node};
    use secp256k1::{Keypair, Message};
    use strata_bridge_common::logging::{self, LoggerConfig};
    use strata_bridge_primitives::scripts::taproot::create_script_spend_hash;
    use strata_bridge_test_utils::prelude::generate_keypair;
    use tracing::info;

    use super::*;

    const N_WATCHTOWERS: usize = 10;
    const DELTA_CONTEST: relative::LockTime = relative::LockTime::from_height(10);

    struct Signer {
        n_of_n_keypair: Keypair,
        watchtower_keypairs: Vec<Keypair>,
    }

    impl Signer {
        fn generate() -> Self {
            let n_of_n_keypair = generate_keypair();
            let watchtower_keypairs = (0..N_WATCHTOWERS).map(|_| generate_keypair()).collect();

            Self {
                n_of_n_keypair,
                watchtower_keypairs,
            }
        }

        fn get_connector(&self) -> ClaimContestConnector {
            let n_of_n_pubkey = self.n_of_n_keypair.x_only_public_key().0;
            let watchtower_pubkeys: Vec<_> = self
                .watchtower_keypairs
                .iter()
                .map(|key| key.x_only_public_key().0)
                .collect();

            ClaimContestConnector::new(
                Network::Regtest,
                n_of_n_pubkey,
                watchtower_pubkeys,
                DELTA_CONTEST,
            )
        }

        fn sign_leaf(&self, leaf_index: usize, sighash: Message) -> ClaimContestWitness {
            let n_of_n_signature = self.n_of_n_keypair.sign_schnorr(sighash);

            match leaf_index.cmp(&self.watchtower_keypairs.len()) {
                Ordering::Less => {
                    let watchtower_signature =
                        self.watchtower_keypairs[leaf_index].sign_schnorr(sighash);
                    let spend_path = ClaimContestSpendPath::Contested {
                        watchtower_index: leaf_index as u32,
                        watchtower_signature,
                    };
                    ClaimContestWitness {
                        n_of_n_signature,
                        spend_path,
                    }
                }
                Ordering::Equal => ClaimContestWitness {
                    n_of_n_signature,
                    spend_path: ClaimContestSpendPath::Uncontested,
                },
                Ordering::Greater => panic!("Leaf index is out of bounds"),
            }
        }
    }

    fn spend_connector(connector: ClaimContestConnector, signer: Signer, leaf_index: usize) {
        logging::init(LoggerConfig::new("connector-p-script-path".to_string()));

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
            script_sig: funded_address.script_pubkey(),
            ..Default::default()
        }];

        let output = vec![
            TxOut {
                value: funding_amount,
                script_pubkey: connector.tx_out().script_pubkey,
            },
            TxOut {
                value: coinbase_amount
                    .checked_sub(funding_amount)
                    .unwrap()
                    .checked_sub(fees)
                    .unwrap(),
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

        assert!(signed_funding_tx.complete);
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
            value: funding_amount.checked_sub(fees).unwrap(),
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

        // Update locktime and sequence for uncontested spend
        // This influences the sighash!
        if leaf_index == connector.n_watchtowers() {
            spending_tx.lock_time =
                absolute::LockTime::from_consensus(connector.delta_contest().to_consensus_u32());
            spending_tx.input[0].sequence = connector.delta_contest().to_sequence();
        }

        let mut sighash_cache = SighashCache::new(&spending_tx);
        let prevouts = [funding_tx.output[0].clone()];
        let leaf_scripts = connector.leaf_scripts();
        let sighash = create_script_spend_hash(
            &mut sighash_cache,
            &leaf_scripts[leaf_index],
            Prevouts::All(&prevouts),
            TapSighashType::Default,
            0,
        )
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

        let tx = btc_client
            .call::<String>("getrawtransaction", &[json!(&spending_txid)])
            .expect("must be able to get transaction");
        let tx = consensus::encode::deserialize_hex::<Transaction>(&tx).expect("must deserialize");

        assert_eq!(spending_txid, tx.compute_txid());
    }

    #[test]
    fn contested_spend() {
        let signer = Signer::generate();
        let connector = signer.get_connector();
        spend_connector(connector, signer, 0);
    }

    #[test]
    fn uncontested_spend() {
        let signer = Signer::generate();
        let connector = signer.get_connector();
        spend_connector(connector, signer, N_WATCHTOWERS);
    }
}
