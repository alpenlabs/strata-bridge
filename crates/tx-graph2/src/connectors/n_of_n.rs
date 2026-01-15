//! This module contains a generic N/N connector.

use bitcoin::{Amount, Network};
use secp256k1::{schnorr, XOnlyPublicKey};

use crate::connectors::{Connector, TaprootWitness};

/// Generic N/N connector.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct NOfNConnector {
    network: Network,
    n_of_n_pubkey: XOnlyPublicKey,
    value: Amount,
}

impl NOfNConnector {
    /// Creates a new connector.
    pub const fn new(network: Network, n_of_n_pubkey: XOnlyPublicKey, value: Amount) -> Self {
        Self {
            network,
            n_of_n_pubkey,
            value,
        }
    }
}

impl Connector for NOfNConnector {
    type SpendPath = NOfNSpend;
    type Witness = schnorr::Signature;

    fn network(&self) -> Network {
        self.network
    }

    fn internal_key(&self) -> XOnlyPublicKey {
        self.n_of_n_pubkey
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

/// Single spend path of a [`NOfNConnector`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct NOfNSpend;

#[cfg(test)]
mod tests {
    use bitcoin::Amount;
    use secp256k1::Keypair;
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::connectors::{
        test_utils::{self, Signer},
        SigningInfo,
    };

    const CONNECTOR_VALUE: Amount = Amount::from_sat(330);

    struct NOfNSigner(Keypair);

    impl test_utils::Signer for NOfNSigner {
        type Connector = NOfNConnector;

        fn generate() -> Self {
            Self(generate_keypair())
        }

        fn get_connector(&self) -> Self::Connector {
            NOfNConnector::new(
                Network::Regtest,
                self.0.x_only_public_key().0,
                CONNECTOR_VALUE,
            )
        }

        fn get_connector_name(&self) -> &'static str {
            "n-of-n"
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
    fn n_of_n_spend() {
        NOfNSigner::assert_connector_is_spendable(NOfNSpend);
    }
}

/// Proptest generators for the `NOfNConnector`.
#[cfg(test)]
pub mod prop_test_generators {
    use proptest::prop_compose;
    use strata_bridge_test_utils::bitcoin::prop_test_generators::{arb_amount, arb_schnorr_key};

    use super::*;

    prop_compose! {
        /// Generates arbitrary `NOfNConnector`.
        pub fn arb_n_of_n_connector()(
            n_of_n_pubkey in arb_schnorr_key(),
            value in arb_amount(),
        ) -> NOfNConnector {
            NOfNConnector::new(Network::Regtest, n_of_n_pubkey, value)
        }
    }
}
