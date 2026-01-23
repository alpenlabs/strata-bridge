//! BIP32 derivation paths for Strata Bridge key hierarchy.
//!
//! # Key Hierarchy Overview
//!
//! All keys derive from a master seed through this crate's [`crate::OperatorKeys::base_xpriv()`],
//! which is rooted at `m/20000'/20'`. From there, additional keys are derived for specific
//! purposes:
//!
//! ```text
//! Master Seed (32 bytes)
//! └── m/20000'/20' (base_xpriv from OperatorKeys)
//!     ├── m/20000'/20'/100' ─────── Operator message signing key (ed25519)
//!     ├── m/20000'/20'/20'/101' ─── MuSig2 signing key (threshold multisig)
//!     ├── m/20000'/20'/20'/102' ─── General wallet key (external funds)
//!     ├── m/20000'/20'/20'/103' ─── Stakechain wallet key (reserved funds)
//!     ├── m/20000'/20'/666'/0' ──── MuSig2 nonce IKM (secnonce generation)
//!     ├── m/20000'/20'/79'/128'/0' ─ WOTS 128-bit IKM
//!     ├── m/20000'/20'/79'/256'/0' ─ WOTS 256-bit IKM
//!     └── m/20000'/20'/80'/0' ───── Stakechain preimage IKM
//! ```
//!
//! # Path Purpose Reference
//!
//! Suffixes below are relative to `crate::OperatorKeys::base_xpriv()` (`m/20000'/20'`).
//!
//! | Path Suffix | Purpose | Consumer |
//! |-------------|---------|----------|
//! | `100'` | Operator message signing key (ed25519) | `p2p-service`, `secret-service`, `dev-cli` |
//! | `20'/101'` | MuSig2 signing key for threshold multisig | `secret-service`, `dev-cli` |
//! | `20'/102'` | General wallet (external funds management) | `operator-wallet`, `secret-service` |
//! | `20'/103'` | Stakechain wallet (stake operations) | `operator-wallet`, `secret-service` |
//! | `666'/0'` | MuSig2 nonce seed material | `secret-service` |
//! | `79'/128'/0'` | WOTS 128-bit initial key material | `secret-service` |
//! | `79'/256'/0'` | WOTS 256-bit initial key material | `secret-service` |
//! | `80'/0'` | Stakechain preimage seed | `secret-service` |
use bitcoin::bip32::ChildNumber;

/// Strata base index for keys.
///
/// # Implementation Details
///
/// The base index is set to 20,000 to ensure that it does not conflict with
/// [BIP-43](https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki)
/// reserved ranges.
pub(crate) const STRATA_BASE_IDX: ChildNumber = ChildNumber::Hardened { index: 20_000 };

/// Strata operator index for keys.
pub(crate) const STRATA_OPERATOR_IDX: ChildNumber = ChildNumber::Hardened { index: 20 };

/// Operator branch under the Strata base path.
///
/// Relative to `m/20000'`, this corresponds to the path: `m/20'`.
pub(crate) const STRATA_OPERATOR_BASE_DERIVATION_PATH: &[ChildNumber] = &[STRATA_OPERATOR_IDX];

/// Operator message index (`m/20000'/20'/100'`).
pub(crate) const STRATA_OPERATOR_MESSAGE_IDX: ChildNumber = ChildNumber::Hardened { index: 100 };

/// Operator MuSig2 index (`m/20000'/20'/101'`).
pub(crate) const STRATA_OPERATOR_WALLET_IDX: ChildNumber = ChildNumber::Hardened { index: 101 };

/// Operator general wallet index (`m/20000'/20'/102'`).
pub(crate) const STRATA_OPERATOR_GENERAL_WALLET_IDX: ChildNumber =
    ChildNumber::Hardened { index: 102 };

/// Operator stakechain wallet index (`m/20000'/20'/103'`).
pub(crate) const STRATA_OPERATOR_STAKECHAIN_WALLET_IDX: ChildNumber =
    ChildNumber::Hardened { index: 103 };

/// Operator message signing path relative to the operator branch (`m/20000'/20'`).
pub(crate) const STRATA_OPERATOR_MESSAGE_DERIVATION_PATH: &[ChildNumber] =
    &[STRATA_OPERATOR_MESSAGE_IDX];

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
pub(crate) const MUSIG2_KEY_PATH: &[ChildNumber] =
    &[STRATA_OPERATOR_IDX, STRATA_OPERATOR_WALLET_IDX];

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
pub(crate) const GENERAL_WALLET_KEY_PATH: &[ChildNumber] =
    &[STRATA_OPERATOR_IDX, STRATA_OPERATOR_GENERAL_WALLET_IDX];

/// Path for the stakechain wallet key
pub(crate) const STAKECHAIN_WALLET_KEY_PATH: &[ChildNumber] =
    &[STRATA_OPERATOR_IDX, STRATA_OPERATOR_STAKECHAIN_WALLET_IDX];
