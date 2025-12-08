//! This module contains a generic timelocked N/N connector.
//!
//! The following connectors are built on top:
//! 1. contest proof, and
//! 2. contest payout, and
//! 3. contest slash, and
//! 4. counterproof_i.

use std::num::NonZero;

use bitcoin::{opcodes, relative, script, Amount, Network, ScriptBuf};
use secp256k1::{schnorr, Scalar, XOnlyPublicKey, SECP256K1};

use crate::connectors::{Connector, TaprootWitness};

/// Generic connector output that is locked in a tap tree:
/// 1. (key path) internal key
/// 2. (single tap leaf) N/N + relative timelock.
///
/// The internal key of the **contest proof** connector,
/// is the N/N key tweaked with the game index.
///
/// The internal key of the **contest payout** connector
/// and of the **contest slash** connector is just the N/N key.
///
/// The internal key of the **counterproof_i** connector is
/// `wt_i_fault * G`, where `G` is the generator point.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct TimelockedNOfNConnector {
    network: Network,
    internal_pubkey: XOnlyPublicKey,
    n_of_n_pubkey: XOnlyPublicKey,
    timelock: relative::LockTime,
}

impl TimelockedNOfNConnector {
    /// Creates a new connector.
    pub const fn new(
        network: Network,
        internal_pubkey: XOnlyPublicKey,
        n_of_n_pubkey: XOnlyPublicKey,
        timelock: relative::LockTime,
    ) -> Self {
        Self {
            network,
            internal_pubkey,
            n_of_n_pubkey,
            timelock,
        }
    }

    /// Creates a new contest proof connector.
    ///
    /// # Panics
    ///
    /// The game index must be less than the secp curve order.
    pub fn new_contest_proof(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        operator_pubkey: XOnlyPublicKey,
        game_index: NonZero<u32>,
        proof_timelock: relative::LockTime,
    ) -> Self {
        let mut tweak_bytes = [0u8; 32];
        tweak_bytes[28..32].copy_from_slice(&game_index.get().to_be_bytes());
        let game_index_tweak = Scalar::from_be_bytes(tweak_bytes)
            .expect("the game index must be less than the secp curve order");
        // This can only fail if the private key of operator_pubkey equals
        // (curve_order - game_index), which is cryptographically impossible
        // for honestly-generated keys.
        let internal_pubkey = operator_pubkey
            .add_tweak(SECP256K1, &game_index_tweak)
            .expect("tweak is valid")
            .0;

        Self {
            network,
            internal_pubkey,
            n_of_n_pubkey,
            timelock: proof_timelock,
        }
    }

    /// Creates a new contest payout connector.
    pub const fn new_contest_payout(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        ack_timelock: relative::LockTime,
    ) -> Self {
        Self {
            network,
            internal_pubkey: n_of_n_pubkey,
            n_of_n_pubkey,
            timelock: ack_timelock,
        }
    }

    /// Creates a new contest slash connector.
    pub const fn new_contest_slash(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        contested_payout_timelock: relative::LockTime,
    ) -> Self {
        Self {
            network,
            internal_pubkey: n_of_n_pubkey,
            n_of_n_pubkey,
            timelock: contested_payout_timelock,
        }
    }

    /// Creates a new counterproof_i connector.
    pub const fn new_counterproof_i(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        wt_i_fault_pubkey: XOnlyPublicKey,
        nack_timelock: relative::LockTime,
    ) -> Self {
        Self {
            network,
            internal_pubkey: wt_i_fault_pubkey,
            n_of_n_pubkey,
            timelock: nack_timelock,
        }
    }

    /// Returns the relative timelock of the connector.
    ///
    /// - For the **contest proof** connector, this is the **proof** timelock.
    /// - For the **contest payout** connector, this is the **ack** timelock.
    /// - For the **contest slash** connector, this is the **contested payout** timelock.
    /// - For the **counterproof_i** connector, this is the **nack** timelock.
    pub const fn timelock(&self) -> relative::LockTime {
        self.timelock
    }
}

impl Connector for TimelockedNOfNConnector {
    type Witness = TimelockedNOfNWitness;

    fn network(&self) -> Network {
        self.network
    }

    fn internal_key(&self) -> XOnlyPublicKey {
        self.internal_pubkey
    }

    fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        let mut scripts = Vec::new();

        let payout_script = script::Builder::new()
            .push_slice(self.n_of_n_pubkey.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            .push_sequence(self.timelock.to_sequence())
            .push_opcode(opcodes::all::OP_CSV)
            .into_script();
        scripts.push(payout_script);

        scripts
    }

    fn value(&self) -> Amount {
        self.script_pubkey().minimal_non_dust()
    }

    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
        match witness {
            TimelockedNOfNWitness::Normal {
                output_key_signature,
            } => TaprootWitness::Key {
                output_key_signature: *output_key_signature,
            },
            TimelockedNOfNWitness::Timeout { n_of_n_signature } => TaprootWitness::Script {
                leaf_index: 0,
                script_inputs: vec![n_of_n_signature.serialize().to_vec()],
            },
        }
    }
}

/// Witness data to spend a [`TimelockedNOfNConnector`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TimelockedNOfNWitness {
    /// The connector is spent before the timeout.
    ///
    /// - The **contest proof** connector is spent in the `Bridge Proof` transaction.
    /// - The **contest payout** connector is spent in the `Bridge Proof Timeout` transaction or in
    ///   the `Watchtower i Ack` transaction.
    /// - The **contest slash** connector is spent in the `Contested Payout` transaction.
    /// - The **counterproof_i** connector is spent in the `Watchtower i Nack` transaction.
    Normal {
        /// Output key signature (key-path spend).
        ///
        /// The output key is the internal key tweaked with the tap tree merkle root.
        ///
        /// The internal key of the...
        /// - **contest proof** connector is the **N/N key tweaked with the game index**.
        /// - **contest payout** connector is the **N/N** key.
        /// - **contest slash** connector is the **N/N** key.
        /// - **counterproof_i** connector is the `wt_i_fault * G` public key.
        output_key_signature: schnorr::Signature,
    },
    /// The connector is spent after the timeout.
    ///
    /// - The **contest proof** connector is spent in the `Bridge Proof Timeout` transaction.
    /// - The **contest payout** connector is spent in the `Contested Payout` transaction.
    /// - The **contest slash** connector is spent in the `Slash` transaction.
    /// - The **counterproof_i** connector is spent in the `Watchtower i Ack` transaction.
    ///
    /// # Warning
    ///
    /// The sequence number of the transaction input needs to be large enough to cover
    /// [`TimelockedNOfNConnector::timelock()`].
    Timeout {
        /// N/N signature.
        n_of_n_signature: schnorr::Signature,
    },
}

#[cfg(test)]
mod tests {
    use bitcoin::key::TapTweak;
    use secp256k1::{Keypair, Message, SECP256K1};
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::connectors::test_utils::Signer;

    const TIMELOCK: relative::LockTime = relative::LockTime::from_height(10);

    struct TimelockedNOfNSigner {
        internal_keypair: Keypair,
        n_of_n_keypair: Keypair,
    }

    impl Signer for TimelockedNOfNSigner {
        type Connector = TimelockedNOfNConnector;

        fn generate() -> Self {
            Self {
                internal_keypair: generate_keypair(),
                n_of_n_keypair: generate_keypair(),
            }
        }

        fn get_connector(&self) -> Self::Connector {
            TimelockedNOfNConnector {
                network: Network::Regtest,
                internal_pubkey: self.internal_keypair.x_only_public_key().0,
                n_of_n_pubkey: self.n_of_n_keypair.x_only_public_key().0,
                timelock: TIMELOCK,
            }
        }

        fn get_connector_name(&self) -> &'static str {
            "timelocked-n-of-n"
        }

        fn get_relative_timelock(&self, leaf_index: usize) -> Option<relative::LockTime> {
            (leaf_index == 0).then_some(TIMELOCK)
        }

        fn sign_leaf(
            &self,
            leaf_index: Option<usize>,
            sighash: Message,
        ) -> <Self::Connector as Connector>::Witness {
            match leaf_index {
                None => {
                    let connector = self.get_connector();
                    let merkle_root = connector.spend_info().merkle_root();
                    let output_keypair = self
                        .internal_keypair
                        .tap_tweak(SECP256K1, merkle_root)
                        .to_keypair();

                    TimelockedNOfNWitness::Normal {
                        output_key_signature: output_keypair.sign_schnorr(sighash),
                    }
                }
                Some(0) => TimelockedNOfNWitness::Timeout {
                    n_of_n_signature: self.n_of_n_keypair.sign_schnorr(sighash),
                },
                Some(_) => panic!("Leaf index is out of bounds"),
            }
        }
    }

    #[test]
    fn normal_spend() {
        let leaf_index = None;
        TimelockedNOfNSigner::assert_connector_is_spendable(leaf_index);
    }

    #[test]
    fn timeout_spend() {
        let leaf_index = Some(0);
        TimelockedNOfNSigner::assert_connector_is_spendable(leaf_index);
    }
}
