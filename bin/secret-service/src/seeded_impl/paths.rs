//! BIP32 paths used for various secret material derivation

use bitcoin::bip32::ChildNumber;

/// Path for initial key material used for 160-bit WOTS keys
pub const WOTS_IKM_160_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 79 },
    ChildNumber::Hardened { index: 160 },
    ChildNumber::Hardened { index: 0 },
];
/// Path for initial key material used for 256-bit WOTS keys
pub const WOTS_IKM_256_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 79 },
    ChildNumber::Hardened { index: 256 },
    ChildNumber::Hardened { index: 0 },
];

/// Path for the Musig2 key
pub const MUSIG2_KEY_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 20 },
    ChildNumber::Hardened { index: 101 },
];
/// Path for initial key material for secnonce generation in musig2
pub const MUSIG2_NONCE_IKM_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 666 },
    ChildNumber::Hardened { index: 0 },
];

/// Path for initial key material for stakechain preimages
pub const STAKECHAIN_PREIMG_IKM_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 80 },
    ChildNumber::Hardened { index: 0 },
];

/// Path for the P2P key
pub const P2P_KEY_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 20 },
    ChildNumber::Hardened { index: 100 },
];

/// Path for the general wallet key
pub const GENERAL_WALLET_KEY_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 20 },
    ChildNumber::Hardened { index: 102 },
];

/// Path for the stakechain wallet key
pub const STAKECHAIN_WALLET_KEY_PATH: &[ChildNumber] = &[
    ChildNumber::Hardened { index: 20 },
    ChildNumber::Hardened { index: 103 },
];
