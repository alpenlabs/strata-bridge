//! BIP32 derivation paths for Strata Bridge key hierarchy.
//!
//! # Key Hierarchy Overview
//!
//! All keys derive from a master seed through the `strata-key-derivation` crate's
//! `OperatorKeys::base_xpriv()` at path `m/20000'/20'`. From there, additional keys
//! are derived for specific purposes:
//!
//! ```text
//! Master Seed (32 bytes)
//! └── m/20000'/20' (base_xpriv from OperatorKeys)
//!     ├── m/.../20'/101' ─── MuSig2 Signing Key (threshold multisig)
//!     ├── m/.../20'/102' ─── General Wallet Key (external funds)
//!     ├── m/.../20'/103' ─── Stakechain Wallet Key (reserved funds)
//!     ├── m/.../666'/0' ──── MuSig2 Nonce IKM (secnonce generation)
//!     ├── m/.../79'/128'/0' ─ WOTS 128-bit IKM
//!     ├── m/.../79'/256'/0' ─ WOTS 256-bit IKM
//!     └── m/.../80'/0' ───── Stakechain Preimage IKM
//! ```
//!
//! # Path Purpose Reference
//!
//! | Path Suffix | Purpose | Consumer |
//! |-------------|---------|----------|
//! | `20'/101'` | MuSig2 signing key for threshold multisig | `secret-service`, `dev-cli` |
//! | `20'/102'` | General wallet (external funds management) | `operator-wallet`, `secret-service` |
//! | `20'/103'` | Stakechain wallet (stake operations) | `operator-wallet`, `secret-service` |
//! | `666'/0'` | MuSig2 nonce seed material | `secret-service` |
//! | `79'/128'/0'` | WOTS 128-bit initial key material | `secret-service` |
//! | `79'/256'/0'` | WOTS 256-bit initial key material | `secret-service` |
//! | `80'/0'` | Stakechain preimage seed | `secret-service` |
use bitcoin::bip32::ChildNumber;

/// Path for initial key material used for 128-bit WOTS keys
pub(crate) const WOTS_IKM_128_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 79 },
    ChildNumber::Hardened { index: 128 },
    ChildNumber::Hardened { index: 0 },
];

/// Path for initial key material used for 256-bit WOTS keys
pub(crate) const WOTS_IKM_256_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 79 },
    ChildNumber::Hardened { index: 256 },
    ChildNumber::Hardened { index: 0 },
];

/// Path for the Musig2 key
pub(crate) const MUSIG2_KEY_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 20 },
    ChildNumber::Hardened { index: 101 },
];
/// Path for initial key material for secnonce generation in musig2
pub(crate) const MUSIG2_NONCE_IKM_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 666 },
    ChildNumber::Hardened { index: 0 },
];

/// Path for initial key material for stakechain preimages
pub(crate) const STAKECHAIN_PREIMG_IKM_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 80 },
    ChildNumber::Hardened { index: 0 },
];

/// Path for the general wallet key
pub(crate) const GENERAL_WALLET_KEY_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 20 },
    ChildNumber::Hardened { index: 102 },
];

/// Path for the stakechain wallet key
pub(crate) const STAKECHAIN_WALLET_KEY_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 20 },
    ChildNumber::Hardened { index: 103 },
];
