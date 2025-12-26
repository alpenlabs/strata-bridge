//! This module contains connectors that follow a pattern in their locking script:
//! 1. (key path) internal key
//! 2. (single tap leaf) timelocked key + relative timelock.
//!
//! These connectors are as follows:
//! 1. contest proof
//! 2. contest payout
//! 3. contest slash
//! 4. counterproof_i
//! 5. deposit request

use std::num::NonZero;

use bitcoin::{
    opcodes,
    psbt::Input,
    relative, script,
    sighash::{Prevouts, SighashCache},
    Amount, Network, ScriptBuf, Transaction, TxOut,
};
use secp256k1::{schnorr, Scalar, XOnlyPublicKey, SECP256K1};

use crate::connectors::{Connector, SigningInfo, TaprootWitness};

/// Generic timelocked connector.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
struct TimelockedConnector {
    network: Network,
    internal_key: XOnlyPublicKey,
    timelocked_key: XOnlyPublicKey,
    timelock: relative::LockTime,
    value: Amount,
}

impl Connector for TimelockedConnector {
    type SpendPath = TimelockedSpendPath;
    type Witness = TimelockedWitness;

    fn network(&self) -> Network {
        self.network
    }

    fn internal_key(&self) -> XOnlyPublicKey {
        self.internal_key
    }

    fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        let mut scripts = Vec::new();

        let payout_script = script::Builder::new()
            .push_slice(self.timelocked_key.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            .push_sequence(self.timelock.to_sequence())
            .push_opcode(opcodes::all::OP_CSV)
            .into_script();
        scripts.push(payout_script);

        scripts
    }

    fn value(&self) -> Amount {
        self.value
    }

    fn to_leaf_index(&self, spend_path: Self::SpendPath) -> Option<usize> {
        match spend_path {
            TimelockedSpendPath::Normal => None,
            TimelockedSpendPath::Timeout => Some(0),
        }
    }

    fn relative_timelock(&self, spend_path: Self::SpendPath) -> Option<relative::LockTime> {
        matches!(spend_path, TimelockedSpendPath::Timeout).then_some(self.timelock)
    }

    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
        match witness {
            TimelockedWitness::Normal {
                output_key_signature,
            } => TaprootWitness::Key {
                output_key_signature: *output_key_signature,
            },
            TimelockedWitness::Timeout {
                timelocked_key_signature: n_of_n_signature,
            } => TaprootWitness::Script {
                leaf_index: 0,
                script_inputs: vec![n_of_n_signature.serialize().to_vec()],
            },
        }
    }
}

/// Creates a newtype wrapper around [`TimelockedConnector`].
///
/// # Example
///
/// ```ignore
/// impl_timelocked_connector! {
///     $(#[doc = "Struct-level documentation."])*
///     struct MyConnector;
/// }
/// ```
macro_rules! impl_timelocked_connector {
    (
        $(#[$struct_attr:meta])*
        pub struct $name:ident;
    ) => {
        $(#[$struct_attr])*
        #[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
        pub struct $name(TimelockedConnector);

        impl Connector for $name {
            type SpendPath = TimelockedSpendPath;
            type Witness = TimelockedWitness;

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

            fn to_leaf_index(&self, spend_path: Self::SpendPath) -> Option<usize> {
                self.0.to_leaf_index(spend_path)
            }

            // FIXME: (@uncomputable) Add sequence method and call it for each txin that uses a connector
            fn relative_timelock(&self, spend_path: Self::SpendPath) -> Option<relative::LockTime> {
                self.0.relative_timelock(spend_path)
            }

            fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
                self.0.get_taproot_witness(witness)
            }
        }
    };
}

impl_timelocked_connector! {
    /// Connector output between `Contest` and:
    /// 1. `Bridge Proof` (normal)
    /// 2. `Bridge Proof Timeout` (timeout).
    ///
    /// The internal key is the operator key tweaked with the game index.
    ///
    /// # Operator key tweak
    ///
    /// The game index is used as the least significant bytes of a secp scalar (all big endian).
    /// This means that the numeric value of the game index is equal to the numeric value of the
    /// resulting scalar. The scalar is then used to tweak the operator key.
    pub struct ContestProofConnector;
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
        let operator_key_tweak = Self::operator_key_tweak(game_index);
        // This can only fail if the private key of operator_pubkey equals
        // (curve_order - game_index), which is cryptographically impossible
        // for honestly-generated keys.
        let internal_key = operator_pubkey
            .add_tweak(SECP256K1, &operator_key_tweak)
            .expect("tweak is valid")
            .0;

        let mut inner = TimelockedConnector {
            network,
            internal_key,
            timelocked_key: n_of_n_pubkey,
            timelock: proof_timelock,
            value: Amount::ZERO,
        };
        inner.value = inner.script_pubkey().minimal_non_dust();
        Self(inner)
    }

    /// Computes the tap tweak for the operator key.
    pub fn operator_key_tweak(game_index: NonZero<u32>) -> Scalar {
        let mut tweak_bytes = [0u8; 32];
        tweak_bytes[28..32].copy_from_slice(&game_index.get().to_be_bytes());
        Scalar::from_be_bytes(tweak_bytes)
            .expect("the game index must be less than the secp curve order")
    }

    /// Helper method to get the signing info of the first input
    /// of the bridge proof transaction.
    pub fn signing_info_bridge_proof(
        &self,
        cache: &mut SighashCache<&Transaction>,
        prevouts: Prevouts<'_, TxOut>,
    ) -> SigningInfo {
        self.get_signing_info(cache, prevouts, TimelockedSpendPath::Normal, 0)
    }

    /// Helper method to finalize the first input of the bridge proof transaction.
    pub fn partially_finalize_bridge_proof(
        &self,
        input: &mut Input,
        operator_signature: schnorr::Signature,
    ) {
        let witness = TimelockedWitness::Normal {
            output_key_signature: operator_signature,
        };
        self.finalize_input(input, &witness);
    }
}

impl_timelocked_connector! {
    /// Connector output between `Contest` and:
    /// 1. `Bridge Proof Timeout` / `Watchtower i Ack` (normal)
    /// 2. `Contested Payout` (timeout).
    ///
    /// The internal key is the N/N key.
    /// The timelocked key is also the N/N key.
    pub struct ContestPayoutConnector;
}

impl ContestPayoutConnector {
    /// Creates a new connector.
    pub fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        ack_timelock: relative::LockTime,
    ) -> Self {
        let mut inner = TimelockedConnector {
            network,
            internal_key: n_of_n_pubkey,
            timelocked_key: n_of_n_pubkey,
            timelock: ack_timelock,
            value: Amount::ZERO,
        };
        inner.value = inner.script_pubkey().minimal_non_dust();
        Self(inner)
    }
}

impl_timelocked_connector! {
    /// Connector output between `Contest` and:
    /// 1. `Contested Payout` (normal)
    /// 2. `Slash` (timeout).
    ///
    /// The internal key is the N/N key.
    /// The timelocked key is also the N/N key.
    pub struct ContestSlashConnector;
}

impl ContestSlashConnector {
    /// Creates a new connector.
    pub fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        contested_payout_timelock: relative::LockTime,
    ) -> Self {
        let mut inner = TimelockedConnector {
            network,
            internal_key: n_of_n_pubkey,
            timelocked_key: n_of_n_pubkey,
            timelock: contested_payout_timelock,
            value: Amount::ZERO,
        };
        inner.value = inner.script_pubkey().minimal_non_dust();
        Self(inner)
    }
}

impl_timelocked_connector! {
    /// Connector output between `Contest` and:
    /// 1. `Watchtower i Nack` (normal)
    /// 2. `Watchtower i Ack` (timeout).
    ///
    /// The internal key is `wt_i_fault * G`, where `G` is the generator point.
    /// The timelocked key is the N/N key.
    pub struct CounterproofConnector;
}

impl CounterproofConnector {
    /// Creates a new connector.
    pub fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        wt_i_fault_pubkey: XOnlyPublicKey,
        nack_timelock: relative::LockTime,
    ) -> Self {
        let mut inner = TimelockedConnector {
            network,
            internal_key: wt_i_fault_pubkey,
            timelocked_key: n_of_n_pubkey,
            timelock: nack_timelock,
            value: Amount::ZERO,
        };
        inner.value = inner.script_pubkey().minimal_non_dust();
        Self(inner)
    }
}

impl_timelocked_connector! {
    /// Connector output between `DepositRequest` and:
    /// 1. `Deposit` (normal)
    /// 2. refund transaction (timeout).
    ///
    /// The internal key is the N/N key.
    /// The timelocked key is the depositor key.
    pub struct DepositRequestConnector;
}

impl DepositRequestConnector {
    /// Creates a new connector.
    pub const fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        depositor_pubkey: XOnlyPublicKey,
        deposit_timelock: relative::LockTime,
        deposit_amount: Amount,
    ) -> Self {
        Self(TimelockedConnector {
            network,
            internal_key: n_of_n_pubkey,
            timelocked_key: depositor_pubkey,
            timelock: deposit_timelock,
            value: deposit_amount,
        })
    }
}

/// Available spending paths for a timelocked connector.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TimelockedSpendPath {
    /// The connector is spent before the timeout.
    Normal,
    /// The connector is spent after the timeout.
    Timeout,
}

// NOTE: (@uncomputable) Sharing the same witness type across connectors
// keeps the code simple, at the cost of a slightly less clear API.
/// Witness data to spend a timelocked connector.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum TimelockedWitness {
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
        /// Signature of the timelocked key.
        timelocked_key_signature: schnorr::Signature,
    },
}

#[cfg(test)]
mod tests {
    use secp256k1::Keypair;
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::connectors::{test_utils::Signer, SigningInfo};

    const TIMELOCK: relative::LockTime = relative::LockTime::from_height(10);

    struct TimelockedNOfNSigner {
        internal_keypair: Keypair,
        n_of_n_keypair: Keypair,
    }

    impl Signer for TimelockedNOfNSigner {
        type Connector = TimelockedConnector;

        fn generate() -> Self {
            Self {
                internal_keypair: generate_keypair(),
                n_of_n_keypair: generate_keypair(),
            }
        }

        fn get_connector(&self) -> Self::Connector {
            let mut connector = TimelockedConnector {
                network: Network::Regtest,
                internal_key: self.internal_keypair.x_only_public_key().0,
                timelocked_key: self.n_of_n_keypair.x_only_public_key().0,
                timelock: TIMELOCK,
                value: Amount::ZERO,
            };
            connector.value = connector.script_pubkey().minimal_non_dust();
            connector
        }

        fn get_connector_name(&self) -> &'static str {
            "timelocked-n-of-n"
        }

        fn sign_leaf(
            &self,
            spend_path: <Self::Connector as Connector>::SpendPath,
            signing_info: SigningInfo,
        ) -> <Self::Connector as Connector>::Witness {
            match spend_path {
                TimelockedSpendPath::Normal => TimelockedWitness::Normal {
                    output_key_signature: signing_info.sign(&self.internal_keypair),
                },
                TimelockedSpendPath::Timeout => TimelockedWitness::Timeout {
                    timelocked_key_signature: signing_info.sign(&self.n_of_n_keypair),
                },
            }
        }
    }

    #[test]
    fn normal_spend() {
        TimelockedNOfNSigner::assert_connector_is_spendable(TimelockedSpendPath::Normal);
    }

    #[test]
    fn timeout_spend() {
        TimelockedNOfNSigner::assert_connector_is_spendable(TimelockedSpendPath::Timeout);
    }
}
