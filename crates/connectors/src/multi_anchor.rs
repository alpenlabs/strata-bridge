//! This module contains the multi anchor.

use bitcoin::{opcodes, script, Amount, Network, ScriptBuf, XOnlyPublicKey};
use secp256k1::schnorr;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::types::WatchtowerIdx;

use crate::{Connector, TaprootWitness};

/// Multi anchor.
///
/// This is a CPFP connector that requires a signature from one key from a fixed set.
/// In other words, this is a keyed anchor using multiple keys.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MultiAnchor {
    network: Network,
    watchtower_keys: Vec<XOnlyPublicKey>,
    value: Amount,
}

impl MultiAnchor {
    /// Creates a new anchor.
    pub const fn new(
        network: Network,
        watchtower_keys: Vec<XOnlyPublicKey>,
        value: Amount,
    ) -> Self {
        Self {
            network,
            watchtower_keys,
            value,
        }
    }
}

impl Connector for MultiAnchor {
    type SpendPath = MultiAnchorSpendPath;
    type Witness = MultiAnchorWitness;

    fn network(&self) -> Network {
        self.network
    }

    // NOTE: (@uncomputable) For equality, each watchtower gets a tap leaf.
    // We don't put a single watchtower into the internal key.
    fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        self.watchtower_keys
            .iter()
            .map(|watchtower_pubkey| {
                script::Builder::new()
                    .push_slice(watchtower_pubkey.serialize())
                    .push_opcode(opcodes::all::OP_CHECKSIG)
                    .into_script()
            })
            .collect()
    }

    fn value(&self) -> Amount {
        self.value
    }

    fn to_leaf_index(&self, spend_path: Self::SpendPath) -> Option<usize> {
        Some(spend_path.watchtower_index as usize) // cast safety: 32-bit arch or higher
    }

    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
        let leaf_index = witness.watchtower_index as usize; // cast safety: 32-bit arch or higher

        TaprootWitness::Script {
            leaf_index,
            script_inputs: vec![witness.watchtower_signature.serialize().to_vec()],
        }
    }
}

/// Available spending paths for a [`MultiAnchor`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct MultiAnchorSpendPath {
    /// Index of the spending watchtower.
    pub watchtower_index: WatchtowerIdx,
}

/// Witness data to spend a [`MultiAnchor`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct MultiAnchorWitness {
    /// Index of the spending watchtower.
    pub watchtower_index: WatchtowerIdx,
    /// Watchtower signature.
    pub watchtower_signature: schnorr::Signature,
}

#[cfg(test)]
mod tests {
    use secp256k1::Keypair;
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::{test_utils::Signer, SigningInfo};

    const N_WATCHTOWERS: u32 = 3;
    const CONNECTOR_VALUE: Amount = Amount::from_sat(330);

    struct MultiAnchorSigner {
        watchtower_keypairs: Vec<Keypair>,
    }

    impl Signer for MultiAnchorSigner {
        type Connector = MultiAnchor;

        fn generate() -> Self {
            Self {
                watchtower_keypairs: (0..N_WATCHTOWERS as usize)
                    .map(|_| generate_keypair())
                    .collect(),
            }
        }

        fn get_connector(&self) -> Self::Connector {
            MultiAnchor::new(
                Network::Regtest,
                self.watchtower_keypairs
                    .iter()
                    .map(|key| key.x_only_public_key().0)
                    .collect(),
                CONNECTOR_VALUE,
            )
        }

        fn get_connector_name(&self) -> &'static str {
            "multi-anchor"
        }

        fn sign_leaf(
            &self,
            spend_path: <Self::Connector as Connector>::SpendPath,
            signing_info: SigningInfo,
        ) -> <Self::Connector as Connector>::Witness {
            MultiAnchorWitness {
                watchtower_index: spend_path.watchtower_index,
                watchtower_signature: signing_info
                    .sign(&self.watchtower_keypairs[spend_path.watchtower_index as usize]),
            }
        }
    }

    #[test]
    fn multi_anchor_spend_first() {
        MultiAnchorSigner::assert_connector_is_spendable(MultiAnchorSpendPath {
            watchtower_index: 0,
        })
    }

    #[test]
    fn multi_anchor_spend_last() {
        MultiAnchorSigner::assert_connector_is_spendable(MultiAnchorSpendPath {
            watchtower_index: 2,
        })
    }
}
