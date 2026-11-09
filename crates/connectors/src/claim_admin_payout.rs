//! This module contains the claim payout connector.

use bitcoin::{Amount, Network, ScriptBuf};
use secp256k1::{schnorr, PublicKey, XOnlyPublicKey};
use strata_bridge_key_deriv::key_agg::derive_musig_0_0;
use strata_bridge_primitives::scripts::{
    prelude::threshold_multisig_script, taproot::TaprootTweak,
};

use crate::{Connector, TaprootWitness};

/// Connector output between `Claim` and:
/// 1. `Uncontested Payout` / `Contested Payout`.
/// 2. `Admin Block Payout`
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClaimAdminPayoutConnector {
    network: Network,
    n_of_n_pubkey: PublicKey,
    admin_pubkeys: Vec<XOnlyPublicKey>,
    admin_threshold: usize,
}

impl ClaimAdminPayoutConnector {
    /// Creates a connector.
    ///
    /// The connector needs the full N/N aggregate public key.
    ///
    /// # Panics
    ///
    /// Panics if `admin_pubkeys` is empty, if `admin_pubkeys` contains duplicate keys, if
    /// `admin_threshold` is zero, or if `admin_threshold` exceeds the number of admin pubkeys.
    pub fn new(
        network: Network,
        n_of_n_pubkey: PublicKey,
        admin_pubkeys: Vec<XOnlyPublicKey>,
        admin_threshold: usize,
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
        }
    }
}

impl Connector for ClaimAdminPayoutConnector {
    type SpendPath = ClaimAdminPayoutSpendPath;
    type Witness = ClaimAdminPayoutWitness;

    fn network(&self) -> Network {
        self.network
    }

    fn internal_key(&self) -> XOnlyPublicKey {
        derive_musig_0_0(self.n_of_n_pubkey)
            .expect("valid aggregate derivation")
            .0
            .x_only_public_key()
            .0
    }

    fn tweak(&self) -> TaprootTweak {
        TaprootTweak::Bip328Key {
            tweak: self.spend_info().merkle_root(),
        }
    }

    fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        vec![threshold_multisig_script(
            &self.admin_pubkeys,
            self.admin_threshold,
        )]
    }

    fn value(&self) -> Amount {
        self.script_pubkey().minimal_non_dust()
    }

    fn to_leaf_index(&self, spend_path: Self::SpendPath) -> Option<usize> {
        match spend_path {
            ClaimAdminPayoutSpendPath::Payout => None,
            ClaimAdminPayoutSpendPath::AdminBlockPayout => Some(0),
        }
    }

    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
        match witness {
            ClaimAdminPayoutWitness::Payout {
                output_key_signature,
            } => TaprootWitness::Key {
                output_key_signature: *output_key_signature,
            },
            ClaimAdminPayoutWitness::AdminBlockPayout { admin_signatures } => {
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
                    "admin block payout requires at least threshold signatures for distinct known admin pubkeys"
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

/// Available spending paths for a [`ClaimAdminPayoutConnector`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ClaimAdminPayoutSpendPath {
    /// The connector is spent in the `Uncontested Payout`
    /// or in the `Contested Payout` transaction.
    Payout,
    /// The connector is spent in the `Admin Block Payout` transaction.
    AdminBlockPayout,
}

/// Witness data to spend a [`ClaimAdminPayoutConnector`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClaimAdminPayoutWitness {
    /// The connector is spent in the `Uncontested Payout`
    /// or in the `Contested Payout` transaction.
    Payout {
        /// Output key signature (key-path spend).
        ///
        /// The output key is the N/N key,
        /// tweaked to become the BIP-328 `/0/0` child,
        /// and tweaked again with the tap root.
        output_key_signature: schnorr::Signature,
    },
    /// The connector is spent in the `Admin Block Payout` transaction.
    AdminBlockPayout {
        /// Admin signatures paired with the pubkey indices they validate against.
        ///
        /// The witness builder ignores unknown or repeated pubkey indices, keeps threshold
        /// signatures in descending pubkey-index order, and emits empty placeholders for known
        /// admin pubkeys that are not selected.
        admin_signatures: Vec<AdminSignature>,
    },
}

#[cfg(test)]
mod tests {
    use std::array;

    use secp256k1::{schnorr, Keypair};
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::{test_utils::Signer, SigningInfo};

    struct ClaimAdminPayoutSigner<const THRESHOLD: usize, const N_ADMINS: usize> {
        n_of_n_keypair: Keypair,
        admin_keypairs: [Keypair; N_ADMINS],
    }

    impl<const THRESHOLD: usize, const N_ADMINS: usize> Signer
        for ClaimAdminPayoutSigner<THRESHOLD, N_ADMINS>
    {
        type Connector = ClaimAdminPayoutConnector;

        fn generate() -> Self {
            assert!(N_ADMINS > 0);
            assert!(THRESHOLD > 0);
            assert!(THRESHOLD <= N_ADMINS);

            Self {
                n_of_n_keypair: generate_keypair(),
                admin_keypairs: array::from_fn(|_| generate_keypair()),
            }
        }

        fn get_connector(&self) -> Self::Connector {
            ClaimAdminPayoutConnector::new(
                Network::Regtest,
                self.n_of_n_keypair.public_key(),
                self.admin_keypairs
                    .iter()
                    .map(|keypair| keypair.x_only_public_key().0)
                    .collect(),
                THRESHOLD,
            )
        }

        fn get_connector_name(&self) -> &'static str {
            "claim-admin-payout"
        }

        fn sign_leaf(
            &self,
            spend_path: <Self::Connector as Connector>::SpendPath,
            signing_info: SigningInfo,
        ) -> <Self::Connector as Connector>::Witness {
            match spend_path {
                ClaimAdminPayoutSpendPath::Payout => ClaimAdminPayoutWitness::Payout {
                    output_key_signature: signing_info.sign(&self.n_of_n_keypair),
                },
                ClaimAdminPayoutSpendPath::AdminBlockPayout => {
                    ClaimAdminPayoutWitness::AdminBlockPayout {
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
                    }
                }
            }
        }
    }

    #[test]
    fn payout_spend() {
        ClaimAdminPayoutSigner::<2, 4>::assert_connector_is_spendable(
            ClaimAdminPayoutSpendPath::Payout,
        );
    }

    #[test]
    fn admin_block_payout_spend_1_of_1() {
        ClaimAdminPayoutSigner::<1, 1>::assert_connector_is_spendable(
            ClaimAdminPayoutSpendPath::AdminBlockPayout,
        );
    }

    #[test]
    fn admin_block_payout_spend_1_of_3() {
        ClaimAdminPayoutSigner::<1, 3>::assert_connector_is_spendable(
            ClaimAdminPayoutSpendPath::AdminBlockPayout,
        );
    }

    #[test]
    fn admin_block_payout_spend_2_of_3() {
        ClaimAdminPayoutSigner::<2, 3>::assert_connector_is_spendable(
            ClaimAdminPayoutSpendPath::AdminBlockPayout,
        );
    }

    #[test]
    fn admin_block_payout_spend_3_of_3() {
        ClaimAdminPayoutSigner::<3, 3>::assert_connector_is_spendable(
            ClaimAdminPayoutSpendPath::AdminBlockPayout,
        );
    }

    #[test]
    fn admin_block_payout_witness_truncates_surplus_indexed_signatures() {
        let signer = ClaimAdminPayoutSigner::<2, 3>::generate();
        let connector = signer.get_connector();
        let signature_0 =
            schnorr::Signature::from_slice(&[0xAA; 64]).expect("signature length is valid");
        let signature_1 =
            schnorr::Signature::from_slice(&[0xBB; 64]).expect("signature length is valid");
        let signature_2 =
            schnorr::Signature::from_slice(&[0xCC; 64]).expect("signature length is valid");
        let witness = ClaimAdminPayoutWitness::AdminBlockPayout {
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
            panic!("admin block payout is a script-path spend");
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
    fn admin_block_payout_witness_ignores_duplicate_indices() {
        let signer = ClaimAdminPayoutSigner::<2, 3>::generate();
        let connector = signer.get_connector();
        let signature_0 =
            schnorr::Signature::from_slice(&[0xAA; 64]).expect("signature length is valid");
        let duplicate_signature =
            schnorr::Signature::from_slice(&[0xBB; 64]).expect("signature length is valid");
        let signature_2 =
            schnorr::Signature::from_slice(&[0xCC; 64]).expect("signature length is valid");
        let witness = ClaimAdminPayoutWitness::AdminBlockPayout {
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
            panic!("admin block payout is a script-path spend");
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
    fn admin_block_payout_witness_ignores_out_of_bounds_indices() {
        let signer = ClaimAdminPayoutSigner::<2, 3>::generate();
        let connector = signer.get_connector();
        let signature_0 =
            schnorr::Signature::from_slice(&[0xAA; 64]).expect("signature length is valid");
        let out_of_bounds_signature =
            schnorr::Signature::from_slice(&[0xBB; 64]).expect("signature length is valid");
        let signature_2 =
            schnorr::Signature::from_slice(&[0xCC; 64]).expect("signature length is valid");
        let witness = ClaimAdminPayoutWitness::AdminBlockPayout {
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
            panic!("admin block payout is a script-path spend");
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
        expected = "admin block payout requires at least threshold signatures for distinct known admin pubkeys"
    )]
    fn admin_block_payout_witness_rejects_below_threshold_signatures() {
        let signer = ClaimAdminPayoutSigner::<2, 3>::generate();
        let connector = signer.get_connector();
        let signature =
            schnorr::Signature::from_slice(&[0xAA; 64]).expect("signature length is valid");
        let duplicate_signature =
            schnorr::Signature::from_slice(&[0xBB; 64]).expect("signature length is valid");
        let out_of_bounds_signature =
            schnorr::Signature::from_slice(&[0xCC; 64]).expect("signature length is valid");
        let witness = ClaimAdminPayoutWitness::AdminBlockPayout {
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

        ClaimAdminPayoutConnector::new(
            Network::Regtest,
            n_of_n_keypair.public_key(),
            vec![admin_pubkey, admin_pubkey],
            2,
        );
    }
}
