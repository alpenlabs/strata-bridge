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
    /// There is 1 operator signature per byte of data.
    pub operator_signatures: Vec<schnorr::Signature>,
}

#[cfg(test)]
mod tests {
    use secp256k1::Keypair;
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::connectors::test_utils::Signer;

    const N_DATA: NonZero<usize> = NonZero::new(10).unwrap();

    struct ContestWatchtowerSigner {
        n_of_n_keypair: Keypair,
        operator_keypair: Keypair,
    }

    impl Signer for ContestWatchtowerSigner {
        type Connector = ContestCounterproofOutput;

        fn generate() -> Self {
            Self {
                n_of_n_keypair: generate_keypair(),
                operator_keypair: generate_keypair(),
            }
        }

        fn get_connector(&self) -> Self::Connector {
            ContestCounterproofOutput {
                network: Network::Regtest,
                n_of_n_pubkey: self.n_of_n_keypair.x_only_public_key().0,
                operator_pubkey: self.operator_keypair.x_only_public_key().0,
                n_data: N_DATA,
            }
        }

        fn get_connector_name(&self) -> &'static str {
            "contest-counterproof"
        }

        fn sign_leaf(
            &self,
            _leaf_index: Option<usize>,
            _sighash: secp256k1::Message,
        ) -> <Self::Connector as Connector>::Witness {
            unimplemented!("use sign_leaf_with_code_separator")
        }

        fn sign_leaf_with_code_separator(
            &self,
            leaf_index: Option<usize>,
            sighashes: &[secp256k1::Message],
        ) -> <Self::Connector as Connector>::Witness {
            if leaf_index != Some(0) {
                panic!("Unsupported leaf index");
            }

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
        ContestWatchtowerSigner::assert_connector_is_spendable(Some(0));
    }
}
