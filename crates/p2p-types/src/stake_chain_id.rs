//! Every deposit needs a unique identifier to exchange (partial) signatures and (public) nonces.
//! This is the role of [`StakeChainId`].

use core::fmt;

use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};

/// A unique identifier of (partial) signatures and (public) nonces exchange session made by
/// hashing unique data related to it.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Deserialize, Serialize)]
pub struct StakeChainId([u8; StakeChainId::SIZE]);

impl StakeChainId {
    /// Size in bytes.
    const SIZE: usize = 32;

    /// Constructs a [`StakeChainId`] from `data` by hashing it.
    pub fn hash(data: &[u8]) -> Self {
        Self(sha256::Hash::const_hash(data).to_byte_array())
    }

    /// Constructs a [`StakeChainId`] from raw bytes.
    ///
    /// Note that the `bytes` should represent a hash.
    pub fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    /// Outputs the [`StakeChainId`] as a vector of raw bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl fmt::Display for StakeChainId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl AsRef<[u8]> for StakeChainId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl From<sha256::Hash> for StakeChainId {
    fn from(value: sha256::Hash) -> Self {
        Self(value.to_byte_array())
    }
}
