//! This module contains the claim payout connector.

use bitcoin::{
    hashes::{sha256, Hash},
    opcodes, Amount, Network, ScriptBuf,
};
use secp256k1::{schnorr, XOnlyPublicKey};

use crate::{Connector, TaprootWitness};

/// Connector output between `Claim` and:
/// 1. `Uncontested Payout` / `Contested Payout`.
/// 2. `Unstaking Block Payout`
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ClaimUnstakingPayoutConnector {
    network: Network,
    n_of_n_pubkey: XOnlyPublicKey,
    unstaking_image: sha256::Hash,
}

impl ClaimUnstakingPayoutConnector {
    /// Creates a new connector.
    ///
    /// The preimage of `unstaking_image` must be 32 bytes long.
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

impl Connector for ClaimUnstakingPayoutConnector {
    type SpendPath = ClaimUnstakingPayoutSpendPath;
    type Witness = ClaimUnstakingPayoutWitness;

    fn network(&self) -> Network {
        self.network
    }

    fn internal_key(&self) -> XOnlyPublicKey {
        self.n_of_n_pubkey
    }

    fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        let unstaking_block_payout_script = ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_SIZE)
            .push_int(0x20)
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_SHA256)
            .push_slice(self.unstaking_image.to_byte_array())
            .push_opcode(opcodes::all::OP_EQUAL)
            .into_script();

        vec![unstaking_block_payout_script]
    }

    fn value(&self) -> Amount {
        self.script_pubkey().minimal_non_dust()
    }

    fn to_leaf_index(&self, spend_path: Self::SpendPath) -> Option<usize> {
        match spend_path {
            ClaimUnstakingPayoutSpendPath::Payout => None,
            ClaimUnstakingPayoutSpendPath::UnstakingBlockPayout => Some(0),
        }
    }

    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
        match witness {
            ClaimUnstakingPayoutWitness::Payout {
                output_key_signature,
            } => TaprootWitness::Key {
                output_key_signature: *output_key_signature,
            },
            ClaimUnstakingPayoutWitness::UnstakingBlockPayout { unstaking_preimage } => {
                TaprootWitness::Script {
                    leaf_index: 0,
                    script_inputs: vec![unstaking_preimage.to_vec()],
                }
            }
        }
    }
}

/// Available spending paths for a [`ClaimUnstakingPayoutConnector`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ClaimUnstakingPayoutSpendPath {
    /// The connector is spent in the `Uncontested Payout`
    /// or in the `Contested Payout` transaction.
    Payout,
    /// The connector is spent in the `Unstaking Block Payout` transaction.
    UnstakingBlockPayout,
}

/// Witness data to spend a [`ClaimUnstakingPayoutConnector`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClaimUnstakingPayoutWitness {
    /// The connector is spent in the `Uncontested Payout`
    /// or in the `Contested Payout` transaction.
    Payout {
        /// Output key signature (key-path spend).
        ///
        /// The output key is the N/N key tweaked with the tap tree merkle root.
        output_key_signature: schnorr::Signature,
    },
    /// The connector is spent in the `Unstaking Block Payout` transaction.
    UnstakingBlockPayout {
        /// Preimage that is revealed when the operator posts the unstaking intent transaction.
        unstaking_preimage: [u8; 32],
    },
}

#[cfg(test)]
mod tests {
    use secp256k1::{rand::random, Keypair};
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::{test_utils::Signer, SigningInfo};

    struct ClaimUnstakingPayoutSigner<const THRESHOLD: usize, const N_ADMINS: usize> {
        n_of_n_keypair: Keypair,
        unstaking_preimage: [u8; 32],
    }

    impl<const THRESHOLD: usize, const N_ADMINS: usize> Signer
        for ClaimUnstakingPayoutSigner<THRESHOLD, N_ADMINS>
    {
        type Connector = ClaimUnstakingPayoutConnector;

        fn generate() -> Self {
            Self {
                n_of_n_keypair: generate_keypair(),
                unstaking_preimage: random::<[u8; 32]>(),
            }
        }

        fn get_connector(&self) -> Self::Connector {
            ClaimUnstakingPayoutConnector::new(
                Network::Regtest,
                self.n_of_n_keypair.x_only_public_key().0,
                sha256::Hash::hash(&self.unstaking_preimage),
            )
        }

        fn get_connector_name(&self) -> &'static str {
            "claim-unstaking-payout"
        }

        fn sign_leaf(
            &self,
            spend_path: <Self::Connector as Connector>::SpendPath,
            signing_info: SigningInfo,
        ) -> <Self::Connector as Connector>::Witness {
            match spend_path {
                ClaimUnstakingPayoutSpendPath::Payout => ClaimUnstakingPayoutWitness::Payout {
                    output_key_signature: signing_info.sign(&self.n_of_n_keypair),
                },
                ClaimUnstakingPayoutSpendPath::UnstakingBlockPayout => {
                    ClaimUnstakingPayoutWitness::UnstakingBlockPayout {
                        unstaking_preimage: self.unstaking_preimage,
                    }
                }
            }
        }
    }

    #[test]
    fn payout_spend() {
        ClaimUnstakingPayoutSigner::<2, 4>::assert_connector_is_spendable(
            ClaimUnstakingPayoutSpendPath::Payout,
        );
    }

    #[test]
    fn unstaking_block_payout_spend() {
        ClaimUnstakingPayoutSigner::<2, 4>::assert_connector_is_spendable(
            ClaimUnstakingPayoutSpendPath::UnstakingBlockPayout,
        );
    }
}
