//! This module contains the claim payout connector.

use bitcoin::{
    hashes::{sha256, Hash},
    opcodes, Amount, Network, ScriptBuf,
};
use secp256k1::{schnorr, XOnlyPublicKey};
use strata_bridge_primitives::scripts::prelude::threshold_multisig_script;

use crate::{Connector, TaprootWitness};

/// Connector output between `Claim` and:
/// 1. `Bridge Proof Timeout`
/// 2. `Uncontested Payout` / `Contested Payout`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClaimPayoutConnector {
    network: Network,
    n_of_n_pubkey: XOnlyPublicKey,
    admin_pubkeys: Vec<XOnlyPublicKey>,
    admin_threshold: usize,
    unstaking_image: sha256::Hash,
}

impl ClaimPayoutConnector {
    /// Creates a new connector.
    ///
    /// The preimage of `unstaking_image` must be 32 bytes long.
    ///
    /// # Panics
    ///
    /// Panics if `admin_pubkeys` is empty, if `admin_pubkeys` contains duplicate keys, if
    /// `admin_threshold` is zero, or if `admin_threshold` exceeds the number of admin pubkeys.
    pub fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        admin_pubkeys: Vec<XOnlyPublicKey>,
        admin_threshold: usize,
        unstaking_image: sha256::Hash,
    ) -> Self {
        assert!(
            !admin_pubkeys.is_empty(),
            "admin multisig requires at least one pubkey"
        );
        assert!(
            admin_threshold > 0,
            "admin multisig threshold must be greater than zero"
        );
        assert!(
            admin_threshold <= admin_pubkeys.len(),
            "admin multisig threshold must not exceed pubkey count"
        );
        assert!(
            admin_pubkeys
                .iter()
                .enumerate()
                .all(|(i, pubkey)| !admin_pubkeys[..i].contains(pubkey)),
            "admin multisig pubkeys must be unique"
        );

        Self {
            network,
            n_of_n_pubkey,
            admin_pubkeys,
            admin_threshold,
            unstaking_image,
        }
    }
}

impl Connector for ClaimPayoutConnector {
    type SpendPath = ClaimPayoutSpendPath;
    type Witness = ClaimPayoutWitness;

    fn network(&self) -> Network {
        self.network
    }

    fn internal_key(&self) -> XOnlyPublicKey {
        self.n_of_n_pubkey
    }

    fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        let mut scripts = Vec::new();

        let admin_burn_script =
            threshold_multisig_script(&self.admin_pubkeys, self.admin_threshold);
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

    fn to_leaf_index(&self, spend_path: Self::SpendPath) -> Option<usize> {
        match spend_path {
            ClaimPayoutSpendPath::Payout => None,
            ClaimPayoutSpendPath::AdminBurn => Some(0),
            ClaimPayoutSpendPath::UnstakingBurn => Some(1),
        }
    }

    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
        match witness {
            ClaimPayoutWitness::Payout {
                output_key_signature,
            } => TaprootWitness::Key {
                output_key_signature: *output_key_signature,
            },
            ClaimPayoutWitness::AdminBurn { admin_signatures } => {
                let mut accepted_signatures = admin_signatures
                    .iter()
                    .copied()
                    .filter(|admin_signature| {
                        admin_signature.pubkey_index < self.admin_pubkeys.len()
                    })
                    .collect::<Vec<_>>();

                // sort first so that the subsequent call to `dedup_by_key` can remove consecutive
                // duplicates
                accepted_signatures.sort_by_key(|sig| sig.pubkey_index);
                accepted_signatures.dedup_by_key(|admin_signature| admin_signature.pubkey_index);

                assert!(
                    accepted_signatures.len() >= self.admin_threshold,
                    "admin burn requires at least threshold signatures for distinct known admin pubkeys"
                );
                accepted_signatures.truncate(self.admin_threshold);

                let script_inputs = (0..self.admin_pubkeys.len())
                    .rev()
                    .map(|pubkey_index| {
                        accepted_signatures
                            .iter()
                            .find(|admin_signature| admin_signature.pubkey_index == pubkey_index)
                            .map(|admin_signature| admin_signature.signature.serialize().to_vec())
                            .unwrap_or_default()
                    })
                    .collect();

                TaprootWitness::Script {
                    leaf_index: 0,
                    script_inputs,
                }
            }
            ClaimPayoutWitness::UnstakingBurn { unstaking_preimage } => TaprootWitness::Script {
                leaf_index: 1,
                script_inputs: vec![unstaking_preimage.to_vec()],
            },
        }
    }
}

/// Signature for a specific admin pubkey position.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct AdminSignature {
    /// Index of the admin pubkey this signature validates against.
    pub pubkey_index: usize,
    /// Signature produced by the admin key at `pubkey_index`.
    pub signature: schnorr::Signature,
}

/// Available spending paths for a [`ClaimPayoutConnector`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ClaimPayoutSpendPath {
    /// The connector is spent in the `Uncontested Payout`
    /// or in the `Contested Payout` transaction.
    Payout,
    /// The connector is spent in the `Admin Burn` transaction.
    AdminBurn,
    /// The connector is spent in the `Unstaking Burn` transaction.
    UnstakingBurn,
}

/// Witness data to spend a [`ClaimPayoutConnector`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClaimPayoutWitness {
    /// The connector is spent in the `Uncontested Payout`
    /// or in the `Contested Payout` transaction.
    Payout {
        /// Output key signature (key-path spend).
        ///
        /// The output key is the N/N key tweaked with the tap tree merkle root.
        output_key_signature: schnorr::Signature,
    },
    /// The connector is spent in the `Admin Burn` transaction.
    AdminBurn {
        /// Admin signatures paired with the pubkey indices they validate against.
        ///
        /// The witness builder ignores unknown or repeated pubkey indices, keeps threshold
        /// signatures in descending pubkey-index order, and emits empty placeholders for known
        /// admin pubkeys that are not selected.
        admin_signatures: Vec<AdminSignature>,
    },
    /// The connector is spent in the `Unstaking Burn` transaction.
    UnstakingBurn {
        /// Preimage that is revealed when the operator posts the unstaking intent transaction.
        unstaking_preimage: [u8; 32],
    },
}

#[cfg(test)]
mod tests {
    use std::array;

    use secp256k1::{rand::random, schnorr, Keypair};
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::{test_utils::Signer, SigningInfo};

    struct ClaimPayoutSigner<const THRESHOLD: usize, const N_ADMINS: usize> {
        n_of_n_keypair: Keypair,
        admin_keypairs: [Keypair; N_ADMINS],
        unstaking_preimage: [u8; 32],
    }

    impl<const THRESHOLD: usize, const N_ADMINS: usize> Signer
        for ClaimPayoutSigner<THRESHOLD, N_ADMINS>
    {
        type Connector = ClaimPayoutConnector;

        fn generate() -> Self {
            assert!(N_ADMINS > 0);
            assert!(THRESHOLD > 0);
            assert!(THRESHOLD <= N_ADMINS);

            Self {
                n_of_n_keypair: generate_keypair(),
                admin_keypairs: array::from_fn(|_| generate_keypair()),
                unstaking_preimage: random::<[u8; 32]>(),
            }
        }

        fn get_connector(&self) -> Self::Connector {
            ClaimPayoutConnector::new(
                Network::Regtest,
                self.n_of_n_keypair.x_only_public_key().0,
                self.admin_keypairs
                    .iter()
                    .map(|keypair| keypair.x_only_public_key().0)
                    .collect(),
                THRESHOLD,
                sha256::Hash::hash(&self.unstaking_preimage),
            )
        }

        fn get_connector_name(&self) -> &'static str {
            "claim-payout"
        }

        fn sign_leaf(
            &self,
            spend_path: <Self::Connector as Connector>::SpendPath,
            signing_info: SigningInfo,
        ) -> <Self::Connector as Connector>::Witness {
            match spend_path {
                ClaimPayoutSpendPath::Payout => ClaimPayoutWitness::Payout {
                    output_key_signature: signing_info.sign(&self.n_of_n_keypair),
                },
                ClaimPayoutSpendPath::AdminBurn => ClaimPayoutWitness::AdminBurn {
                    admin_signatures: self
                        .admin_keypairs
                        .iter()
                        .enumerate()
                        .take(THRESHOLD)
                        .map(|(pubkey_index, keypair)| AdminSignature {
                            pubkey_index,
                            signature: signing_info.sign(keypair),
                        })
                        .collect(),
                },
                ClaimPayoutSpendPath::UnstakingBurn => ClaimPayoutWitness::UnstakingBurn {
                    unstaking_preimage: self.unstaking_preimage,
                },
            }
        }
    }

    #[test]
    fn payout_spend() {
        ClaimPayoutSigner::<2, 4>::assert_connector_is_spendable(ClaimPayoutSpendPath::Payout);
    }

    #[test]
    fn admin_burn_spend_1_of_1() {
        ClaimPayoutSigner::<1, 1>::assert_connector_is_spendable(ClaimPayoutSpendPath::AdminBurn);
    }

    #[test]
    fn admin_burn_spend_1_of_3() {
        ClaimPayoutSigner::<1, 3>::assert_connector_is_spendable(ClaimPayoutSpendPath::AdminBurn);
    }

    #[test]
    fn admin_burn_spend_2_of_3() {
        ClaimPayoutSigner::<2, 3>::assert_connector_is_spendable(ClaimPayoutSpendPath::AdminBurn);
    }

    #[test]
    fn admin_burn_spend_3_of_3() {
        ClaimPayoutSigner::<3, 3>::assert_connector_is_spendable(ClaimPayoutSpendPath::AdminBurn);
    }

    #[test]
    fn admin_burn_witness_truncates_surplus_indexed_signatures() {
        let signer = ClaimPayoutSigner::<2, 3>::generate();
        let connector = signer.get_connector();
        let signature_0 =
            schnorr::Signature::from_slice(&[0xAA; 64]).expect("signature length is valid");
        let signature_1 =
            schnorr::Signature::from_slice(&[0xBB; 64]).expect("signature length is valid");
        let signature_2 =
            schnorr::Signature::from_slice(&[0xCC; 64]).expect("signature length is valid");
        let witness = ClaimPayoutWitness::AdminBurn {
            admin_signatures: vec![
                AdminSignature {
                    pubkey_index: 0,
                    signature: signature_0,
                },
                AdminSignature {
                    pubkey_index: 2,
                    signature: signature_2,
                },
                AdminSignature {
                    pubkey_index: 1,
                    signature: signature_1,
                },
            ],
        };

        let TaprootWitness::Script { script_inputs, .. } = connector.get_taproot_witness(&witness)
        else {
            panic!("admin burn is a script-path spend");
        };

        assert_eq!(
            script_inputs,
            vec![
                Vec::new(),
                signature_1.serialize().to_vec(),
                signature_0.serialize().to_vec(),
            ]
        );
    }

    #[test]
    fn admin_burn_witness_ignores_duplicate_indices() {
        let signer = ClaimPayoutSigner::<2, 3>::generate();
        let connector = signer.get_connector();
        let signature_0 =
            schnorr::Signature::from_slice(&[0xAA; 64]).expect("signature length is valid");
        let duplicate_signature =
            schnorr::Signature::from_slice(&[0xBB; 64]).expect("signature length is valid");
        let signature_2 =
            schnorr::Signature::from_slice(&[0xCC; 64]).expect("signature length is valid");
        let witness = ClaimPayoutWitness::AdminBurn {
            admin_signatures: vec![
                AdminSignature {
                    pubkey_index: 0,
                    signature: signature_0,
                },
                AdminSignature {
                    pubkey_index: 0,
                    signature: duplicate_signature,
                },
                AdminSignature {
                    pubkey_index: 2,
                    signature: signature_2,
                },
            ],
        };

        let TaprootWitness::Script { script_inputs, .. } = connector.get_taproot_witness(&witness)
        else {
            panic!("admin burn is a script-path spend");
        };

        assert_eq!(
            script_inputs,
            vec![
                signature_2.serialize().to_vec(),
                Vec::new(),
                signature_0.serialize().to_vec()
            ]
        );
    }

    #[test]
    fn admin_burn_witness_ignores_out_of_bounds_indices() {
        let signer = ClaimPayoutSigner::<2, 3>::generate();
        let connector = signer.get_connector();
        let signature_0 =
            schnorr::Signature::from_slice(&[0xAA; 64]).expect("signature length is valid");
        let out_of_bounds_signature =
            schnorr::Signature::from_slice(&[0xBB; 64]).expect("signature length is valid");
        let signature_2 =
            schnorr::Signature::from_slice(&[0xCC; 64]).expect("signature length is valid");
        let witness = ClaimPayoutWitness::AdminBurn {
            admin_signatures: vec![
                AdminSignature {
                    pubkey_index: 0,
                    signature: signature_0,
                },
                AdminSignature {
                    pubkey_index: 3,
                    signature: out_of_bounds_signature,
                },
                AdminSignature {
                    pubkey_index: 2,
                    signature: signature_2,
                },
            ],
        };

        let TaprootWitness::Script { script_inputs, .. } = connector.get_taproot_witness(&witness)
        else {
            panic!("admin burn is a script-path spend");
        };

        assert_eq!(
            script_inputs,
            vec![
                signature_2.serialize().to_vec(),
                Vec::new(),
                signature_0.serialize().to_vec()
            ]
        );
    }

    #[test]
    #[should_panic(
        expected = "admin burn requires at least threshold signatures for distinct known admin pubkeys"
    )]
    fn admin_burn_witness_rejects_below_threshold_signatures() {
        let signer = ClaimPayoutSigner::<2, 3>::generate();
        let connector = signer.get_connector();
        let signature =
            schnorr::Signature::from_slice(&[0xAA; 64]).expect("signature length is valid");
        let duplicate_signature =
            schnorr::Signature::from_slice(&[0xBB; 64]).expect("signature length is valid");
        let out_of_bounds_signature =
            schnorr::Signature::from_slice(&[0xCC; 64]).expect("signature length is valid");
        let witness = ClaimPayoutWitness::AdminBurn {
            admin_signatures: vec![
                AdminSignature {
                    pubkey_index: 0,
                    signature,
                },
                AdminSignature {
                    pubkey_index: 0,
                    signature: duplicate_signature,
                },
                AdminSignature {
                    pubkey_index: 3,
                    signature: out_of_bounds_signature,
                },
            ],
        };

        connector.get_taproot_witness(&witness);
    }

    #[test]
    #[should_panic(expected = "admin multisig pubkeys must be unique")]
    fn connector_rejects_duplicate_admin_pubkeys() {
        let n_of_n_keypair = generate_keypair();
        let admin_keypair = generate_keypair();
        let admin_pubkey = admin_keypair.x_only_public_key().0;

        ClaimPayoutConnector::new(
            Network::Regtest,
            n_of_n_keypair.x_only_public_key().0,
            vec![admin_pubkey, admin_pubkey],
            2,
            sha256::Hash::hash(&random::<[u8; 32]>()),
        );
    }

    #[test]
    fn unstaking_burn_spend() {
        ClaimPayoutSigner::<2, 4>::assert_connector_is_spendable(
            ClaimPayoutSpendPath::UnstakingBurn,
        );
    }
}
