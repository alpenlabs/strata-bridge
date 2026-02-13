//! This module contains rkyv wrappers for various remote types.
//!
//! These are not intended to be used directly and therefore have no documentation.
//!
//! These are intended to be used with `#[rkyv(with = ...)]` to allow rkyv to serialize and
//! deserialize these remote types.

use bitcoin::hashes::Hash as _;
use rkyv::{Archive, Deserialize, Serialize};

#[derive(
    Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Archive, Serialize, Deserialize,
)]
#[rkyv(remote = bitcoin::OutPoint)]
pub struct OutPoint {
    /// The referenced transaction's txid.
    #[rkyv(with = Txid)]
    pub txid: bitcoin::Txid,
    /// The index of the referenced output in its transaction's vout.
    pub vout: u32,
}

impl From<bitcoin::OutPoint> for OutPoint {
    fn from(value: bitcoin::OutPoint) -> Self {
        Self {
            txid: value.txid,
            vout: value.vout,
        }
    }
}

impl From<OutPoint> for bitcoin::OutPoint {
    fn from(value: OutPoint) -> Self {
        bitcoin::OutPoint {
            txid: value.txid,
            vout: value.vout,
        }
    }
}

#[derive(
    Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Archive, Serialize, Deserialize,
)]
#[rkyv(remote = bitcoin::Txid)]
pub struct Txid(
    #[rkyv(with = Hash, getter = bitcoin::Txid::as_raw_hash)] bitcoin::hashes::sha256d::Hash,
);

impl From<bitcoin::Txid> for Txid {
    fn from(value: bitcoin::Txid) -> Self {
        Self(value.to_raw_hash())
    }
}

impl From<Txid> for bitcoin::Txid {
    fn from(value: Txid) -> Self {
        bitcoin::Txid::from_raw_hash(value.0)
    }
}

#[derive(
    Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Archive, Serialize, Deserialize,
)]
#[repr(transparent)]
pub struct TapNodeHash([u8; 32]);

impl From<bitcoin::taproot::TapNodeHash> for TapNodeHash {
    fn from(value: bitcoin::taproot::TapNodeHash) -> Self {
        Self(value.to_byte_array())
    }
}

impl From<TapNodeHash> for bitcoin::taproot::TapNodeHash {
    fn from(value: TapNodeHash) -> Self {
        bitcoin::taproot::TapNodeHash::from_byte_array(value.0)
    }
}

#[derive(
    Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord, Archive, Serialize, Deserialize,
)]
#[repr(transparent)]
#[rkyv(remote = bitcoin::hashes::sha256d::Hash)]
pub struct Hash(#[rkyv(getter = bitcoin::hashes::sha256d::Hash::as_byte_array)] [u8; 32]);

impl From<bitcoin::hashes::sha256d::Hash> for Hash {
    fn from(value: bitcoin::hashes::sha256d::Hash) -> Self {
        Self(*value.as_byte_array())
    }
}

impl From<Hash> for bitcoin::hashes::sha256d::Hash {
    fn from(value: Hash) -> Self {
        bitcoin::hashes::sha256d::Hash::from_byte_array(value.0)
    }
}
