//! This module contains the claim payout connector.

use bitcoin::{
    hashes::{sha256, Hash},
    opcodes, Amount, Network, ScriptBuf,
};
use secp256k1::{schnorr, XOnlyPublicKey};

use crate::connectors::{Connector, TaprootWitness};

/// Connector output between `Claim` and the payouts.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ClaimPayoutConnector {
    network: Network,
    n_of_n_pubkey: XOnlyPublicKey,
    admin_pubkey: XOnlyPublicKey,
    unstaking_image: sha256::Hash,
}

impl ClaimPayoutConnector {
    /// Creates a new connector.
    ///
    /// The preimage of `unstaking_image` must be 32 bytes long.
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
}

impl Connector for ClaimPayoutConnector {
    type Witness = ClaimPayoutWitness;

    fn network(&self) -> Network {
        self.network
    }

    fn internal_key(&self) -> XOnlyPublicKey {
        self.n_of_n_pubkey
    }

    fn leaf_scripts(&self) -> Vec<ScriptBuf> {
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

    fn value(&self) -> Amount {
        self.script_pubkey().minimal_non_dust()
    }

    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
        match witness {
            ClaimPayoutWitness::Payout {
                output_key_signature,
            } => TaprootWitness::Key {
                output_key_signature: *output_key_signature,
            },
            ClaimPayoutWitness::AdminBurn { admin_signature } => TaprootWitness::Script {
                leaf_index: 0,
                script_inputs: vec![admin_signature.serialize().to_vec()],
            },
            ClaimPayoutWitness::UnstakingBurn { unstaking_preimage } => TaprootWitness::Script {
                leaf_index: 1,
                script_inputs: vec![unstaking_preimage.to_vec()],
            },
        }
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
    use bitcoin::key::TapTweak;
    use secp256k1::{rand::random, Keypair, SECP256K1};
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::connectors::test_utils::Signer;

    struct ClaimPayoutSigner {
        n_of_n_keypair: Keypair,
        admin_keypair: Keypair,
        unstaking_preimage: [u8; 32],
    }

    impl Signer for ClaimPayoutSigner {
        type Connector = ClaimPayoutConnector;

        fn generate() -> Self {
            Self {
                n_of_n_keypair: generate_keypair(),
                admin_keypair: generate_keypair(),
                unstaking_preimage: random::<[u8; 32]>(),
            }
        }

        fn get_connector(&self) -> Self::Connector {
            ClaimPayoutConnector::new(
                Network::Regtest,
                self.n_of_n_keypair.x_only_public_key().0,
                self.admin_keypair.x_only_public_key().0,
                sha256::Hash::hash(&self.unstaking_preimage),
            )
        }

        fn get_connector_name(&self) -> &'static str {
            "claim-payout"
        }

        fn sign_leaf(
            &self,
            leaf_index: Option<usize>,
            sighash: secp256k1::Message,
        ) -> <Self::Connector as Connector>::Witness {
            match leaf_index {
                None => {
                    let connector = self.get_connector();
                    let merkle_root = connector.spend_info().merkle_root();
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

    #[test]
    fn payout_spend() {
        ClaimPayoutSigner::assert_connector_is_spendable(None);
    }

    #[test]
    fn admin_burn_spend() {
        ClaimPayoutSigner::assert_connector_is_spendable(Some(0));
    }

    #[test]
    fn unstaking_burn_spend() {
        ClaimPayoutSigner::assert_connector_is_spendable(Some(1));
    }
}
