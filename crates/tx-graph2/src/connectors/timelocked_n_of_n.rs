//! This module contains connectors that follow a timelock pattern in their locking script:
//! 1. contest proof
//! 2. contest payout
//! 3. contest slash
//! 4. counterproof_i

use std::num::NonZero;

use bitcoin::{
    opcodes, relative, script,
    sighash::{Prevouts, SighashCache},
    Amount, Network, ScriptBuf, Transaction, TxOut,
};
use secp256k1::{schnorr, Scalar, XOnlyPublicKey, SECP256K1};

use crate::connectors::{Connector, SigningInfo, TaprootWitness};

/// Generic connector output that is locked in a tap tree:
/// 1. (key path) internal key
/// 2. (single tap leaf) N/N + relative timelock.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct TimelockedNOfNConnector {
    network: Network,
    internal_pubkey: XOnlyPublicKey,
    n_of_n_pubkey: XOnlyPublicKey,
    timelock: relative::LockTime,
}

impl TimelockedNOfNConnector {
    /// Returns the signing info for the normal spend path.
    fn normal_signing_info(
        &self,
        cache: &mut SighashCache<&Transaction>,
        prevouts: Prevouts<'_, TxOut>,
        input_index: usize,
    ) -> SigningInfo {
        SigningInfo {
            sighash: self.compute_sighash(None, cache, prevouts, input_index),
            tweak: Some(self.tweak()),
        }
    }

    /// Returns the signing info for the timeout spend path.
    fn timeout_signing_info(
        &self,
        cache: &mut SighashCache<&Transaction>,
        prevouts: Prevouts<'_, TxOut>,
        input_index: usize,
    ) -> SigningInfo {
        SigningInfo {
            sighash: self.compute_sighash(Some(0), cache, prevouts, input_index),
            tweak: None,
        }
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

/// Creates a newtype wrapper around [`TimelockedNOfNConnector`].
///
/// This macro generates the struct definition with the standard derives, a `Connector`
/// implementation that delegates all methods to the inner `TimelockedNOfNConnector`,
/// and timelock/signing info accessor methods with custom names and documentation.
///
/// # Example
///
/// ```ignore
/// impl_timelocked_connector! {
///     $(#[doc = "Struct-level documentation."])*
///     struct MyConnector;
///
///     $(#[doc = "Documentation for the timelock method."])*
///     timelock = my_timelock,
///
///     $(#[doc = "Documentation for the normal signing info method."])*
///     normal_signing_info = my_normal_signing_info,
///
///     $(#[doc = "Documentation for the timeout signing info method."])*
///     timeout_signing_info = my_timeout_signing_info,
/// }
/// ```
macro_rules! impl_timelocked_connector {
    (
        $(#[$struct_attr:meta])*
        pub struct $name:ident;

        $(#[$timelock_attr:meta])*
        timelock = $timelock_name:ident,

        $(#[$normal_signing_info_attr:meta])*
        normal_signing_info = $normal_signing_info_name:ident,

        $(#[$timeout_signing_info_attr:meta])*
        timeout_signing_info = $timeout_signing_info_name:ident,
    ) => {
        $(#[$struct_attr])*
        #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
        pub struct $name(TimelockedNOfNConnector);

        impl $name {
            $(#[$timelock_attr])*
            pub const fn $timelock_name(&self) -> relative::LockTime {
                self.0.timelock
            }

            $(#[$normal_signing_info_attr])*
            pub fn $normal_signing_info_name(
                &self,
                cache: &mut SighashCache<&Transaction>,
                prevouts: Prevouts<'_, TxOut>,
                input_index: usize,
            ) -> SigningInfo {
                self.0.normal_signing_info(cache, prevouts, input_index)
            }

            $(#[$timeout_signing_info_attr])*
            pub fn $timeout_signing_info_name(
                &self,
                cache: &mut SighashCache<&Transaction>,
                prevouts: Prevouts<'_, TxOut>,
                input_index: usize,
            ) -> SigningInfo {
                self.0.timeout_signing_info(cache, prevouts, input_index)
            }
        }

        impl Connector for $name {
            type Witness = TimelockedNOfNWitness;

            fn network(&self) -> Network {
                self.0.network()
            }

            fn internal_key(&self) -> XOnlyPublicKey {
                self.0.internal_key()
            }

            fn leaf_scripts(&self) -> Vec<ScriptBuf> {
                self.0.leaf_scripts()
            }

            fn value(&self) -> Amount {
                self.0.value()
            }

            fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
                self.0.get_taproot_witness(witness)
            }
        }
    };
}

impl_timelocked_connector! {
    /// Connector output between `Contest` and `Bridge Proof` / `Bridge Proof Timeout`.
    ///
    /// The internal key is the operator key tweaked with the game index.
    ///
    /// # Operator key tweak
    ///
    /// The game index is used as the least significant bytes of a secp scalar (all big endian).
    /// This means that the numeric value of the game index is equal to the numeric value of the
    /// resulting scalar. The scalar is then used to tweak the operator key.
    pub struct ContestProofConnector;

    /// Returns the relative proof timelock of the connector.
    timelock = proof_timelock,

    /// Returns the signing info for the `Bridge Proof` spend path.
    normal_signing_info = proof_signing_info,

    /// Returns the signing info for the `Bridge Proof Timeout` spend path.
    timeout_signing_info = proof_timeout_signing_info,
}

impl ContestProofConnector {
    /// Creates a connector.
    ///
    /// # Panics
    ///
    /// This method panics if the game index is greater than or equal to the secp curve order.
    pub fn new(
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

        Self(TimelockedNOfNConnector {
            network,
            internal_pubkey,
            n_of_n_pubkey,
            timelock: proof_timelock,
        })
    }
}

impl_timelocked_connector! {
    /// Connector output between `Contest` and
    /// `Bridge Proof Timeout` / `Watchtower i Ack` / `Contested Payout`.
    ///
    /// The internal key is the N/N key.
    pub struct ContestPayoutConnector;

    /// Returns the relative ack timelock of the connector.
    timelock = ack_timelock,

    /// Returns the signing info for the `Bridge Proof Timeout`
    /// or the `Watchtower i Ack` spend path.
    normal_signing_info = ack_signing_info,

    /// Returns the signing info for the `Contested Payout` spend path.
    timeout_signing_info = contested_payout_signing_info,
}

impl ContestPayoutConnector {
    /// Creates a new connector.
    pub const fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        ack_timelock: relative::LockTime,
    ) -> Self {
        Self(TimelockedNOfNConnector {
            network,
            internal_pubkey: n_of_n_pubkey,
            n_of_n_pubkey,
            timelock: ack_timelock,
        })
    }
}

impl_timelocked_connector! {
    /// Connector output between `Contest` and `Contested Payout` / `Slash`.
    ///
    /// The internal key is the N/N key.
    pub struct ContestSlashConnector;

    /// Returns the relative contested payout timelock of the connector.
    timelock = contested_payout_timelock,

    /// Returns the signing info for the `Contested Payout` spend path.
    normal_signing_info = contested_payout_signing_info,

    /// Returns the signing info for the `Slash` spend path.
    timeout_signing_info = slash_signing_info,
}

impl ContestSlashConnector {
    /// Creates a new connector.
    pub const fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        contested_payout_timelock: relative::LockTime,
    ) -> Self {
        Self(TimelockedNOfNConnector {
            network,
            internal_pubkey: n_of_n_pubkey,
            n_of_n_pubkey,
            timelock: contested_payout_timelock,
        })
    }
}

impl_timelocked_connector! {
    /// Connector output between `Contest` and `Watchtower i Nack` / `Watchtower i Ack`.
    ///
    /// The internal key is `wt_i_fault * G`, where `G` is the generator point.
    pub struct CounterproofConnector;

    /// Returns the relative nack timelock of the connector.
    timelock = nack_timelock,

    /// Returns the signing info for the `Watchtower i Nack` spend path.
    normal_signing_info = nack_signing_info,

    /// Returns the signing info for the `Watchtower i Ack` spend path.
    timeout_signing_info = ack_signing_info,
}

impl CounterproofConnector {
    /// Creates a new connector.
    pub const fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        wt_i_fault_pubkey: XOnlyPublicKey,
        nack_timelock: relative::LockTime,
    ) -> Self {
        Self(TimelockedNOfNConnector {
            network,
            internal_pubkey: wt_i_fault_pubkey,
            n_of_n_pubkey,
            timelock: nack_timelock,
        })
    }
}

// NOTE: (@uncomputable) Sharing the same witness type across connectors
// keeps the code simple, at the cost of a slightly less clear API.
// When finalizing transactions, callers will likely never see this type,
// so it should be fine.
/// Witness data to spend a timelocked connector.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TimelockedNOfNWitness {
    /// The connector is spent before the timeout.
    Normal {
        /// Output key signature (key-path spend).
        ///
        /// The output key is the internal key tweaked with the tap tree merkle root.
        output_key_signature: schnorr::Signature,
    },
    /// The connector is spent after the timeout.
    ///
    /// # Warning
    ///
    /// The sequence number of the transaction input needs to be large enough to cover
    /// the connector's timelock.
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
