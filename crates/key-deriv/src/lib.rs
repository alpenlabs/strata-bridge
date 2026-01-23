//! Key derivation primitives for Strata Bridge.
//!
//! This crate provides utilities for deriving operator keys and all bridge-specific
//! key material from a master seed.
//!
//! # Usage
//!
//! ```rust,ignore
//! use bitcoin::{bip32::Xpriv, Network};
//! use strata_bridge_key_deriv::{Musig2Keys, OperatorKeys, WalletKeys};
//!
//! // Create OperatorKeys from seed
//! let xpriv = Xpriv::new_master(Network::Regtest, &seed)?;
//! let keys = OperatorKeys::new(&xpriv)?;
//!
//! // Derive wallet keys
//! let wallet_keys = WalletKeys::derive(keys.base_xpriv())?;
//! let general_pubkey = wallet_keys.general_pubkey();
//! let stakechain_pubkey = wallet_keys.stakechain_pubkey();
//!
//! // Generate P2TR addresses
//! let general_addr = wallet_keys.general_p2tr_address(Network::Regtest);
//!
//! // Derive MuSig2 keys
//! let musig2 = Musig2Keys::derive(keys.base_xpriv())?;
//! let musig2_pubkey = musig2.pubkey();
//! ```
//!
//! # Key Hierarchy
//!
//! All keys derive from a master seed through `OperatorKeys::base_xpriv()` (`m/20000'`).
//! Use the provided structs ([`WalletKeys`], [`Musig2Keys`], [`WotsIkm`],
//! [`StakechainPreimageIkm`]) to derive keys at the correct paths.

pub mod address;
pub mod derive;
mod keys;

// Internal module - paths are obscured to prevent direct usage and ensure consistency
mod paths;

// Re-export commonly used items from derive
// Re-export address utility
pub use address::p2tr_address;
pub use derive::{
    DerivationError,
    // Opaque wrapper types
    GeneralWalletKey,
    Musig2Keypair,
    // Grouped structs
    Musig2Keys,
    Musig2NonceIkm,
    StakechainPreimageIkm,
    StakechainWalletKey,
    WalletKeys,
    WotsIkm,
    WotsIkm128,
    WotsIkm256,
};
pub use keys::OperatorKeys;
