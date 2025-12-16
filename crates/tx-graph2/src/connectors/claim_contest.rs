//! This module contains the claim contest connector.

use bitcoin::{
    opcodes, relative, script,
    sighash::{Prevouts, SighashCache},
    Amount, Network, ScriptBuf, Transaction, TxOut,
};
use secp256k1::{schnorr, XOnlyPublicKey};

use crate::connectors::{Connector, SigningInfo, TaprootWitness};

/// Connector output between `Claim` and:
/// 1. `UncontestedPayout`, and
/// 2. `Contest`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ClaimContestConnector {
    network: Network,
    n_of_n_pubkey: XOnlyPublicKey,
    watchtower_pubkeys: Vec<XOnlyPublicKey>,
    contest_timelock: relative::LockTime,
}

impl ClaimContestConnector {
    /// Creates a new connector.
    pub const fn new(
        network: Network,
        n_of_n_pubkey: XOnlyPublicKey,
        watchtower_pubkeys: Vec<XOnlyPublicKey>,
        contest_timelock: relative::LockTime,
    ) -> Self {
        Self {
            network,
            n_of_n_pubkey,
            watchtower_pubkeys,
            contest_timelock,
        }
    }

    /// Returns the number of watchtowers for the connector.
    pub const fn n_watchtowers(&self) -> usize {
        self.watchtower_pubkeys.len()
    }

    /// Returns the relative contest timelock of the connector.
    pub const fn contest_timelock(&self) -> relative::LockTime {
        self.contest_timelock
    }

    /// Returns the signing info for the contested spend path.
    pub fn contested_signing_info(
        &self,
        cache: &mut SighashCache<&Transaction>,
        prevouts: Prevouts<'_, TxOut>,
        input_index: usize,
        watchtower_index: usize,
    ) -> SigningInfo {
        SigningInfo {
            sighash: self.compute_sighash(Some(watchtower_index), cache, prevouts, input_index),
            tweak: None,
        }
    }

    /// Returns the signing info for the uncontested spend path.
    pub fn uncontested_signing_info(
        &self,
        cache: &mut SighashCache<&Transaction>,
        prevouts: Prevouts<'_, TxOut>,
        input_index: usize,
    ) -> SigningInfo {
        SigningInfo {
            sighash: self.compute_sighash(Some(self.n_watchtowers()), cache, prevouts, input_index),
            tweak: None,
        }
    }
}

impl Connector for ClaimContestConnector {
    type Witness = ClaimContestWitness;

    fn network(&self) -> Network {
        self.network
    }

    fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        let mut scripts = Vec::new();

        for watchtower_pubkey in &self.watchtower_pubkeys {
            let contest_script = script::Builder::new()
                .push_slice(self.n_of_n_pubkey.serialize())
                .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
                .push_slice(watchtower_pubkey.serialize())
                .push_opcode(opcodes::all::OP_CHECKSIG)
                .into_script();
            scripts.push(contest_script);
        }

        let uncontested_payout_script = script::Builder::new()
            .push_slice(self.n_of_n_pubkey.serialize())
            .push_opcode(opcodes::all::OP_CHECKSIGVERIFY)
            .push_sequence(self.contest_timelock.to_sequence())
            .push_opcode(opcodes::all::OP_CSV)
            .into_script();
        scripts.push(uncontested_payout_script);

        scripts
    }

    fn value(&self) -> Amount {
        let minimal_non_dust = self.script_pubkey().minimal_non_dust();
        // TODO: (@uncomputable): Replace magic number 3 with constant from contest transaction,
        // once the code exists
        minimal_non_dust * (3 * self.n_watchtowers() as u64)
    }

    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
        match witness.spend_path {
            ClaimContestSpendPath::Contested {
                watchtower_index,
                watchtower_signature,
            } => TaprootWitness::Script {
                leaf_index: watchtower_index as usize,
                script_inputs: vec![
                    watchtower_signature.serialize().to_vec(),
                    witness.n_of_n_signature.serialize().to_vec(),
                ],
            },
            ClaimContestSpendPath::Uncontested => TaprootWitness::Script {
                leaf_index: self.n_watchtowers(),
                script_inputs: vec![witness.n_of_n_signature.serialize().to_vec()],
            },
        }
    }
}

/// Witness data to spend a [`ClaimContestConnector`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct ClaimContestWitness {
    /// N/N signature.
    ///
    /// This signature is required for all spending paths.
    pub n_of_n_signature: schnorr::Signature,
    /// Used spending path.
    pub spend_path: ClaimContestSpendPath,
}

/// Available spending paths for a [`ClaimContestConnector`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ClaimContestSpendPath {
    /// The connector is spent in the `Contest` transaction.
    Contested {
        /// Index of the spending watchtower.
        watchtower_index: u32,
        /// Signature of the spending watchtower.
        watchtower_signature: schnorr::Signature,
    },
    /// The connector is spent in the `UncontestedPayout` transaction.
    ///
    /// # Warning
    ///
    /// The sequence number of the transaction input needs to be large enough to cover
    /// [`ClaimContestConnector::contest_timelock()`].
    Uncontested,
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;

    use secp256k1::{Keypair, Message};
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::connectors::test_utils::Signer;

    const N_WATCHTOWERS: usize = 10;
    const DELTA_CONTEST: relative::LockTime = relative::LockTime::from_height(10);

    struct ClaimContestSigner {
        n_of_n_keypair: Keypair,
        watchtower_keypairs: Vec<Keypair>,
    }

    impl Signer for ClaimContestSigner {
        type Connector = ClaimContestConnector;

        fn generate() -> Self {
            Self {
                n_of_n_keypair: generate_keypair(),
                watchtower_keypairs: (0..N_WATCHTOWERS).map(|_| generate_keypair()).collect(),
            }
        }

        fn get_connector(&self) -> Self::Connector {
            ClaimContestConnector::new(
                Network::Regtest,
                self.n_of_n_keypair.x_only_public_key().0,
                self.watchtower_keypairs
                    .iter()
                    .map(|key| key.x_only_public_key().0)
                    .collect(),
                DELTA_CONTEST,
            )
        }

        fn get_connector_name(&self) -> &'static str {
            "claim-contest"
        }

        fn get_relative_timelock(&self, leaf_index: usize) -> Option<relative::LockTime> {
            (leaf_index == self.watchtower_keypairs.len()).then_some(DELTA_CONTEST)
        }

        fn sign_leaf(
            &self,
            leaf_index: Option<usize>,
            sighash: Message,
        ) -> <Self::Connector as Connector>::Witness {
            let leaf_index = leaf_index.expect("connector has no key-path spend");
            let n_of_n_signature = self.n_of_n_keypair.sign_schnorr(sighash);

            match leaf_index.cmp(&self.watchtower_keypairs.len()) {
                Ordering::Less => {
                    let watchtower_signature =
                        self.watchtower_keypairs[leaf_index].sign_schnorr(sighash);
                    let spend_path = ClaimContestSpendPath::Contested {
                        watchtower_index: leaf_index as u32,
                        watchtower_signature,
                    };
                    ClaimContestWitness {
                        n_of_n_signature,
                        spend_path,
                    }
                }
                Ordering::Equal => ClaimContestWitness {
                    n_of_n_signature,
                    spend_path: ClaimContestSpendPath::Uncontested,
                },
                Ordering::Greater => panic!("Leaf index is out of bounds"),
            }
        }
    }

    #[test]
    fn contested_spend() {
        let leaf_index = Some(0);
        ClaimContestSigner::assert_connector_is_spendable(leaf_index);
    }

    #[test]
    fn uncontested_spend() {
        let leaf_index = Some(N_WATCHTOWERS);
        ClaimContestSigner::assert_connector_is_spendable(leaf_index);
    }
}
