//! This module contains the unstaking intent output.

use bitcoin::{
    hashes::{sha256, Hash},
    opcodes, Amount, Network, ScriptBuf,
};
use secp256k1::{schnorr, XOnlyPublicKey};

use crate::{Connector, TaprootWitness};

/// Output between `Stake` and `Unstaking Intent`.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct UnstakingIntentOutput {
    network: Network,
    n_of_n_pubkey: XOnlyPublicKey,
    unstaking_image: sha256::Hash,
}

impl UnstakingIntentOutput {
    /// Creates a new connector.
    pub const fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        unstaking_image: sha256::Hash,
    ) -> Self {
        Self {
            network,
            n_of_n_pubkey,
            unstaking_image,
        }
    }
}

impl Connector for UnstakingIntentOutput {
    type SpendPath = UnstakingIntentSpend;
    type Witness = UnstakingIntentWitness;

    fn network(&self) -> Network {
        self.network
    }

    fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        let unstaking_intent_script = ScriptBuf::builder()
            .push_slice(self.n_of_n_pubkey.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            .push_opcode(opcodes::all::OP_SIZE)
            .push_int(0x20)
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_SHA256)
            .push_slice(self.unstaking_image.to_byte_array())
            .push_opcode(opcodes::all::OP_EQUAL)
            .into_script();

        vec![unstaking_intent_script]
    }

    fn value(&self) -> Amount {
        self.script_pubkey().minimal_non_dust()
    }

    fn to_leaf_index(&self, _spend_path: Self::SpendPath) -> Option<usize> {
        Some(0)
    }

    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
        TaprootWitness::Script {
            leaf_index: 0,
            script_inputs: vec![
                witness.unstaking_preimage.to_vec(),
                witness.n_of_n_signature.serialize().to_vec(),
            ],
        }
    }
}

/// The single spend path for a [`UnstakingIntentOutput`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct UnstakingIntentSpend;

/// Witness data to spend a [`UnstakingIntentOutput`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct UnstakingIntentWitness {
    /// N/N signature.
    pub n_of_n_signature: schnorr::Signature,
    /// Unstaking preimage.
    pub unstaking_preimage: [u8; 32],
}

#[cfg(test)]
mod tests {
    use secp256k1::{rand::random, Keypair};
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::{test_utils::Signer, SigningInfo};

    struct UnstakingIntentSigner {
        n_of_n_keypair: Keypair,
        unstaking_preimage: [u8; 32],
    }

    impl Signer for UnstakingIntentSigner {
        type Connector = UnstakingIntentOutput;

        fn generate() -> Self {
            Self {
                n_of_n_keypair: generate_keypair(),
                unstaking_preimage: random::<[u8; 32]>(),
            }
        }

        fn get_connector(&self) -> Self::Connector {
            UnstakingIntentOutput::new(
                Network::Regtest,
                self.n_of_n_keypair.x_only_public_key().0,
                sha256::Hash::hash(&self.unstaking_preimage),
            )
        }

        fn get_connector_name(&self) -> &'static str {
            "unstaking-intent"
        }

        fn sign_leaf(
            &self,
            _spend_path: <Self::Connector as Connector>::SpendPath,
            signing_info: SigningInfo,
        ) -> <Self::Connector as Connector>::Witness {
            UnstakingIntentWitness {
                n_of_n_signature: signing_info.sign(&self.n_of_n_keypair),
                unstaking_preimage: self.unstaking_preimage,
            }
        }
    }

    #[test]
    fn unstaking_intent_spend() {
        UnstakingIntentSigner::assert_connector_is_spendable(UnstakingIntentSpend);
    }
}
