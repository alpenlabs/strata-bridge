//! P2TR address generation utilities.
//!
//! Provides functions to generate Pay-to-Taproot addresses from public keys.

use bitcoin::{Address, Network, XOnlyPublicKey, key::TapTweak};
use secp256k1::SECP256K1;

use crate::derive::WalletKeys;

/// Generate a P2TR address from an x-only public key.
///
/// Uses key-path spending only (no script tree).
#[must_use]
pub fn p2tr_address(pubkey: XOnlyPublicKey, network: Network) -> Address {
    let (tweaked, _) = pubkey.tap_tweak(SECP256K1, None);
    Address::p2tr_tweaked(tweaked, network)
}

impl WalletKeys {
    /// Generate the general wallet's P2TR address.
    pub fn general_p2tr_address(&self, network: Network) -> Address {
        p2tr_address(self.general_pubkey(), network)
    }

    /// Generate the stakechain wallet's P2TR address.
    pub fn stakechain_p2tr_address(&self, network: Network) -> Address {
        p2tr_address(self.stakechain_pubkey(), network)
    }
}
