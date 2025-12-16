//! This module contains a generic N/N connector.

use bitcoin::{
    sighash::{Prevouts, SighashCache},
    Amount, Network, Transaction, TxOut,
};
use secp256k1::{schnorr, XOnlyPublicKey};

use crate::connectors::{Connector, SigningInfo, TaprootWitness};

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

    /// Returns the signing info for the single spend path.
    pub fn signing_info(
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
}

impl Connector for NOfNConnector {
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

    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness {
        TaprootWitness::Key {
            output_key_signature: *witness,
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{key::TapTweak, Amount};
    use secp256k1::{Keypair, Message, SECP256K1};
    use strata_bridge_test_utils::prelude::generate_keypair;

    use super::*;
    use crate::connectors::test_utils::{self, Signer};

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
            leaf_index: Option<usize>,
            sighash: Message,
        ) -> <Self::Connector as Connector>::Witness {
            assert!(leaf_index.is_none(), "connector has no script-path spend");

            let connector = self.get_connector();
            let merkle_root = connector.spend_info().merkle_root();
            let output_keypair = self.0.tap_tweak(SECP256K1, merkle_root).to_keypair();

            output_keypair.sign_schnorr(sighash)
        }
    }

    #[test]
    fn n_of_n_spend() {
        let leaf_index = None;
        NOfNSigner::assert_connector_is_spendable(leaf_index);
    }
}
