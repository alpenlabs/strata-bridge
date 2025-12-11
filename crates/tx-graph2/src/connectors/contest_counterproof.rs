//! This module contains the claim counterproof output.

use std::num::NonZero;

use bitcoin::{opcodes, script, Amount, Network, ScriptBuf};
use secp256k1::{schnorr, XOnlyPublicKey};

use crate::connectors::{Connector, TaprootWitness};

/// Output between `Contest` and `Watchtower i Counterproof`.
///
/// The output requires a series of operator signatures for spending.
/// Each operator signature comes from an adaptor,
/// which publishes one byte of Mosaic data.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ContestCounterproofOutput {
    network: Network,
    n_of_n_pubkey: XOnlyPublicKey,
    operator_pubkey: XOnlyPublicKey,
    n_data: NonZero<usize>,
}

impl ContestCounterproofOutput {
    /// Creates a new connector.
    ///
    /// `n_data` is the length of the data that will be published onchain.
    /// This is equal to the number of required operator signatures.
    pub const fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        operator_pubkey: XOnlyPublicKey,
        n_data: NonZero<usize>,
    ) -> Self {
        Self {
            network,
            n_of_n_pubkey,
            operator_pubkey,
            n_data,
        }
    }

    /// Returns the length of the data that will be published onchain.
    ///
    /// This is 1 operator signature per byte of data.
    pub const fn n_data(&self) -> NonZero<usize> {
        self.n_data
    }
}

// Strictly speaking, this is not a connector output.
// However, we still implement the [`Connector`] trait for convenience.
impl Connector for ContestCounterproofOutput {
    type Witness = ContestCounterproofWitness;

    fn network(&self) -> Network {
        self.network
    }

    fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        let mut builder = script::Builder::new()
            .push_slice(self.n_of_n_pubkey.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            .push_slice(self.operator_pubkey.serialize());

        for _ in 0..self.n_data.get() - 1 {
            builder = builder
                .push_opcode(opcodes::all::OP_TUCK)
                .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
                .push_opcode(opcodes::all::OP_CODESEPARATOR);
        }

        let counterproof_script = builder.push_opcode(opcodes::all::OP_CHECKSIG).into_script();
        vec![counterproof_script]
    }

    fn value(&self) -> Amount {
        self.script_pubkey().minimal_non_dust()
    }

    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
        TaprootWitness::Script {
            leaf_index: 0,
            script_inputs: witness
                .operator_signatures
                .iter()
                .rev()
                .map(|sig| sig.serialize().to_vec())
                .chain(std::iter::once(
                    witness.n_of_n_signature.serialize().to_vec(),
                ))
                .collect(),
        }
    }
}

/// Witness data to spend a [`ContestCounterproofOutput`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ContestCounterproofWitness {
    /// N/N signature.
    pub n_of_n_signature: schnorr::Signature,
    /// Operator signatures.
    ///
    /// There is 1 operator signature per byte of data that will be published onchain.
    pub operator_signatures: Vec<schnorr::Signature>,
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        absolute,
        psbt::Psbt,
        sighash::{Prevouts, SighashCache},
        transaction, OutPoint, Transaction, TxOut,
    };
    use secp256k1::Keypair;
    use strata_bridge_primitives::scripts::prelude::create_tx_ins;
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::connectors::test_utils::BitcoinNode;

    const N_DATA: NonZero<usize> = NonZero::new(10).unwrap();

    struct ContestWatchtowerSigner {
        n_of_n_keypair: Keypair,
        operator_keypair: Keypair,
    }

    impl ContestWatchtowerSigner {
        fn generate() -> Self {
            Self {
                n_of_n_keypair: generate_keypair(),
                operator_keypair: generate_keypair(),
            }
        }

        fn get_connector(&self) -> ContestCounterproofOutput {
            ContestCounterproofOutput {
                network: Network::Regtest,
                n_of_n_pubkey: self.n_of_n_keypair.x_only_public_key().0,
                operator_pubkey: self.operator_keypair.x_only_public_key().0,
                n_data: N_DATA,
            }
        }

        fn sign_leaf(&self, sighashes: &[secp256k1::Message]) -> ContestCounterproofWitness {
            assert!(sighashes.len() == N_DATA.get());
            let n_of_n_signature = self.n_of_n_keypair.sign_schnorr(sighashes[0]);
            let operator_signatures = sighashes
                .iter()
                .copied()
                .map(|sighash| self.operator_keypair.sign_schnorr(sighash))
                .collect();

            ContestCounterproofWitness {
                n_of_n_signature,
                operator_signatures,
            }
        }
    }

    #[test]
    fn counterproof_spend() {
        let mut node = BitcoinNode::new();
        let signer = ContestWatchtowerSigner::generate();
        let connector = signer.get_connector();
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
        let spending_tx = Transaction {
            version: transaction::Version(2),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        // Sign the spending transaction
        let leaf_index = 0;
        let mut cache = SighashCache::new(&spending_tx);
        let utxos = [connector.tx_out(), node.coinbase_tx_out()];
        let prevouts = Prevouts::All(&utxos);
        let input_index = 0;
        let sighashes = connector.compute_sighashes_with_code_separator(
            leaf_index,
            &mut cache,
            prevouts,
            input_index,
        );
        let witness = signer.sign_leaf(&sighashes);

        let mut psbt = Psbt::from_unsigned_tx(spending_tx).unwrap();
        psbt.inputs[0].witness_utxo = Some(connector.tx_out());
        psbt.inputs[1].witness_utxo = Some(node.coinbase_tx_out());
        connector.finalize_input(&mut psbt.inputs[0], &witness);

        let spending_tx = psbt.extract_tx().expect("should be able to extract tx");
        let _ = node.sign_and_broadcast(&spending_tx);
    }
}
