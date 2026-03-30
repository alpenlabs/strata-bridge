//! [`rkyv`] remote wrappers for types that don't natively support rkyv.
use bitcoin::{hashes::Hash as _, Txid};

/// rkyv remote wrapper for `bitcoin::OutPoint`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(remote = bitcoin::OutPoint)]
pub struct RkyvOutPoint {
    #[rkyv(with = RkyvTxid)]
    txid: bitcoin::Txid,
    vout: u32,
}

impl From<bitcoin::OutPoint> for RkyvOutPoint {
    fn from(value: bitcoin::OutPoint) -> Self {
        Self {
            txid: value.txid,
            vout: value.vout,
        }
    }
}

impl From<RkyvOutPoint> for bitcoin::OutPoint {
    fn from(value: RkyvOutPoint) -> Self {
        bitcoin::OutPoint {
            txid: value.txid,
            vout: value.vout,
        }
    }
}

/// rkyv remote wrapper for `bitcoin::Txid`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize,
)]
#[rkyv(remote = Txid)]
pub struct RkyvTxid(#[rkyv(getter = txid_to_bytes)] [u8; 32]);

impl From<bitcoin::Txid> for RkyvTxid {
    fn from(value: Txid) -> Self {
        Self(value.to_byte_array())
    }
}

impl From<RkyvTxid> for bitcoin::Txid {
    fn from(value: RkyvTxid) -> Self {
        Txid::from_byte_array(value.0)
    }
}

fn txid_to_bytes(txid: &Txid) -> [u8; 32] {
    txid.to_byte_array()
}
