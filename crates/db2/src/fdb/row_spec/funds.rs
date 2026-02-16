//! Row spec for fund OutPoints.

use std::convert::Infallible;

use bitcoin::{OutPoint, Txid, hashes::Hash};
use foundationdb::tuple::PackError;
use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};

use super::kv::{KVRowSpec, PackableKey, SerializableValue};
use crate::{fdb::dirs::Directories, types::FundingPurpose};

/// Key for a funds row: `(DepositIdx, OperatorIdx, FundingPurpose)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundsKey {
    /// Deposit index.
    pub deposit_idx: DepositIdx,
    /// Operator index.
    pub operator_idx: OperatorIdx,
    /// Which transaction these outpoints fund.
    pub purpose: FundingPurpose,
}

/// Error when unpacking a [`FundsKey`] from bytes.
#[derive(Debug)]
pub enum FundsKeyUnpackError {
    /// FDB tuple layer failed to decode the key.
    Pack(PackError),
    /// The purpose discriminant is not a known [`FundingPurpose`] variant.
    InvalidPurpose(u8),
}

impl PackableKey for FundsKey {
    type PackingError = Infallible;
    type UnpackingError = FundsKeyUnpackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs.funds.pack::<(u32, u32, u32)>(&(
            self.deposit_idx,
            self.operator_idx,
            self.purpose as u32,
        )))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (deposit_idx, operator_idx, purpose_raw) = dirs
            .funds
            .unpack::<(u32, u32, u32)>(bytes)
            .map_err(FundsKeyUnpackError::Pack)?;
        let purpose_byte = u8::try_from(purpose_raw)
            .map_err(|_| FundsKeyUnpackError::InvalidPurpose(purpose_raw as u8))?;
        let purpose = FundingPurpose::from_u8(purpose_byte)
            .ok_or(FundsKeyUnpackError::InvalidPurpose(purpose_byte))?;
        Ok(Self {
            deposit_idx,
            operator_idx,
            purpose,
        })
    }
}

/// Value for a funds row: a list of `OutPoint`s, stored as
/// concatenated 36-byte entries (32-byte txid + 4-byte little-endian vout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FundsValue(pub Vec<OutPoint>);

/// Error when the byte slice length is not a multiple of 36.
#[derive(Debug)]
pub struct InvalidOutPointBytes {
    /// The actual length of the byte slice.
    pub len: usize,
}

impl SerializableValue for FundsValue {
    type SerializeError = Infallible;
    type DeserializeError = InvalidOutPointBytes;
    type Serialized = Vec<u8>;

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        let mut buf = Vec::with_capacity(self.0.len() * 36);
        for outpoint in &self.0 {
            buf.extend_from_slice(outpoint.txid.as_raw_hash().as_ref());
            buf.extend_from_slice(&outpoint.vout.to_le_bytes());
        }
        Ok(buf)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        if !bytes.len().is_multiple_of(36) {
            return Err(InvalidOutPointBytes { len: bytes.len() });
        }
        let mut outpoints = Vec::with_capacity(bytes.len() / 36);
        for chunk in bytes.chunks_exact(36) {
            let txid =
                Txid::from_slice(&chunk[..32]).expect("chunk is exactly 32 bytes for txid portion");
            let vout = u32::from_le_bytes(chunk[32..36].try_into().expect("4 bytes for vout"));
            outpoints.push(OutPoint { txid, vout });
        }
        Ok(Self(outpoints))
    }
}

/// ZST for the funds row spec.
#[derive(Debug)]
pub struct FundsRowSpec;

impl KVRowSpec for FundsRowSpec {
    type Key = FundsKey;
    type Value = FundsValue;
}
