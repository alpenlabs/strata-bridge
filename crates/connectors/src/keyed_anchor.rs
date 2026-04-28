//! This module contains the keyed anchor.

use bitcoin::{Amount, Network, XOnlyPublicKey};
use secp256k1::schnorr;
use serde::{Deserialize, Serialize};

use crate::{Connector, TaprootWitness};

/// Keyed anchor.
///
/// This is a CPFP connector that requires a given key.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct KeyedAnchor {
    network: Network,
    anchor_key: XOnlyPublicKey,
    value: Amount,
}

impl KeyedAnchor {
    /// Creates a new anchor.
    pub const fn new(network: Network, anchor_key: XOnlyPublicKey, value: Amount) -> Self {
        Self {
            network,
            anchor_key,
            value,
        }
    }
}

impl Connector for KeyedAnchor {
    type SpendPath = KeyedAnchorSpend;
    type Witness = schnorr::Signature;

    fn network(&self) -> Network {
        self.network
    }

    fn internal_key(&self) -> XOnlyPublicKey {
        self.anchor_key
    }

    fn value(&self) -> Amount {
        self.value
    }

    fn to_leaf_index(&self, _spend_path: Self::SpendPath) -> Option<usize> {
        None
    }

    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
        TaprootWitness::Key {
            output_key_signature: *witness,
        }
    }
}

/// Single spend path of a [`KeyedAnchor`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct KeyedAnchorSpend;

#[cfg(test)]
mod tests {
    use secp256k1::Keypair;
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::{
        test_utils::{self, Signer},
        SigningInfo,
    };

    const CONNECTOR_VALUE: Amount = Amount::from_sat(330);

    struct KeyedAnchorSigner(Keypair);

    impl test_utils::Signer for KeyedAnchorSigner {
        type Connector = KeyedAnchor;

        fn generate() -> Self {
            Self(generate_keypair())
        }

        fn get_connector(&self) -> Self::Connector {
            KeyedAnchor::new(
                Network::Regtest,
                self.0.x_only_public_key().0,
                CONNECTOR_VALUE,
            )
        }

        fn get_connector_name(&self) -> &'static str {
            "keyed-anchor"
        }

        fn sign_leaf(
            &self,
            _spend_path: <Self::Connector as Connector>::SpendPath,
            signing_info: SigningInfo,
        ) -> <Self::Connector as Connector>::Witness {
            signing_info.sign(&self.0)
        }
    }

    #[test]
    fn keyed_anchor_spend() {
        KeyedAnchorSigner::assert_connector_is_spendable(KeyedAnchorSpend);
    }
}
