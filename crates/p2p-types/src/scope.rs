//! Every deposit needs a unique identifier to deposit setup information,
//! which is primarily WOTS PKs.
//! This is the role of [`Scope`].

use core::fmt;

use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};

/// A unique identifier of deposit setup made by hashing unique data related to it.
#[derive(
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Debug,
    Deserialize,
    Serialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub struct Scope(ScopeBytes);
/// Required to work around some rkyv_derive limitations.
type ScopeBytes = [u8; Scope::SIZE];

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Scope {
    /// Size in bytes.
    const SIZE: usize = 32;

    /// Constructs a [`Scope`] from `data` by hashing it.
    pub fn hash(data: &[u8]) -> Self {
        Self(sha256::Hash::hash(data).to_byte_array())
    }

    /// Constructs a [`Scope`] from raw bytes.
    ///
    /// Note that the `bytes` should represent a hash.
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self(bytes)
    }

    /// Outputs the [`Scope`] as a vector of raw bytes.
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

impl AsRef<[u8; Scope::SIZE]> for Scope {
    fn as_ref(&self) -> &[u8; Scope::SIZE] {
        &self.0
    }
}

impl From<sha256::Hash> for Scope {
    fn from(value: sha256::Hash) -> Self {
        Self(value.to_byte_array())
    }
}
