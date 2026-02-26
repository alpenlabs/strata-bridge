//! Row specs for claim-funding and withdrawal-funding outpoints.

use std::convert::Infallible;

use bitcoin::{OutPoint, Txid, hashes::Hash};
use foundationdb::tuple::PackError;
use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};

use super::kv::{KVRowSpec, PackableKey, SerializableValue};
use crate::fdb::dirs::Directories;

const SERIALIZED_TXID_SIZE: usize = 32;
const SERIALIZED_VOUT_SIZE: usize = 4;
/// Size of a serialized `OutPoint` in bytes.
pub const SERIALIZED_OUTPOINT_SIZE: usize = SERIALIZED_TXID_SIZE + SERIALIZED_VOUT_SIZE;

/// Error when the byte slice length is not a multiple of [`SERIALIZED_OUTPOINT_SIZE`].
#[derive(Debug)]
pub struct InvalidOutPointBytes {
    /// The actual length of the byte slice.
    pub len: usize,
}

fn serialize_outpoints(outpoints: &[OutPoint]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(outpoints.len() * SERIALIZED_OUTPOINT_SIZE);
    for outpoint in outpoints {
        buf.extend_from_slice(outpoint.txid.as_raw_hash().as_ref());
        buf.extend_from_slice(&outpoint.vout.to_le_bytes());
    }
    buf
}

fn deserialize_outpoints(bytes: &[u8]) -> Result<Vec<OutPoint>, InvalidOutPointBytes> {
    if !bytes.len().is_multiple_of(SERIALIZED_OUTPOINT_SIZE) {
        return Err(InvalidOutPointBytes { len: bytes.len() });
    }
    let mut outpoints = Vec::with_capacity(bytes.len() / SERIALIZED_OUTPOINT_SIZE);
    for chunk in bytes.chunks_exact(SERIALIZED_OUTPOINT_SIZE) {
        let txid = Txid::from_slice(&chunk[..SERIALIZED_TXID_SIZE]).unwrap_or_else(|_| {
            panic!(
                "Invalid Txid bytes: expected {} bytes, got {}",
                SERIALIZED_TXID_SIZE,
                chunk.len()
            )
        });
        let vout = u32::from_le_bytes(
            chunk[SERIALIZED_TXID_SIZE..SERIALIZED_OUTPOINT_SIZE]
                .try_into()
                .unwrap_or_else(|_| {
                    panic!(
                        "Invalid vout bytes: expected {} bytes, got {}",
                        SERIALIZED_VOUT_SIZE,
                        chunk.len() - SERIALIZED_TXID_SIZE
                    )
                }),
        );
        outpoints.push(OutPoint { txid, vout });
    }
    Ok(outpoints)
}

/// Key for claim-funding rows: `(DepositIdx, OperatorIdx)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimFundingKey {
    /// Deposit index.
    pub deposit_idx: DepositIdx,
    /// Operator index.
    pub operator_idx: OperatorIdx,
}

impl PackableKey for ClaimFundingKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs
            .claim_funds
            .pack::<(u32, u32)>(&(self.deposit_idx, self.operator_idx)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (deposit_idx, operator_idx) = dirs.claim_funds.unpack::<(u32, u32)>(bytes)?;
        Ok(Self {
            deposit_idx,
            operator_idx,
        })
    }
}

/// Value for a claim-funding row: a single `OutPoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimFundingValue(pub OutPoint);

impl SerializableValue for ClaimFundingValue {
    type SerializeError = Infallible;
    type DeserializeError = InvalidOutPointBytes;
    type Serialized = [u8; SERIALIZED_OUTPOINT_SIZE];

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        let outpoint = self.0;
        let mut out = [0u8; SERIALIZED_OUTPOINT_SIZE];
        out[..SERIALIZED_TXID_SIZE].copy_from_slice(outpoint.txid.as_raw_hash().as_ref());
        out[SERIALIZED_TXID_SIZE..].copy_from_slice(&outpoint.vout.to_le_bytes());
        Ok(out)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        let outpoints = deserialize_outpoints(bytes)?;
        if outpoints.len() != 1 {
            return Err(InvalidOutPointBytes { len: bytes.len() });
        }
        let outpoint = outpoints[0];
        Ok(Self(outpoint))
    }
}

/// ZST for claim-funding rows.
#[derive(Debug)]
pub struct ClaimFundingRowSpec;

impl KVRowSpec for ClaimFundingRowSpec {
    type Key = ClaimFundingKey;
    type Value = ClaimFundingValue;
}

/// Key for withdrawal-funding rows: `DepositIdx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalFundingKey {
    /// Deposit index.
    pub deposit_idx: DepositIdx,
}

impl PackableKey for WithdrawalFundingKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs.fulfillment_funds.pack::<(u32,)>(&(self.deposit_idx,)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (deposit_idx,) = dirs.fulfillment_funds.unpack::<(u32,)>(bytes)?;
        Ok(Self { deposit_idx })
    }
}

/// Value for a withdrawal-funding row: a list of `OutPoint`s.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalFundingValue(pub Vec<OutPoint>);

impl SerializableValue for WithdrawalFundingValue {
    type SerializeError = Infallible;
    type DeserializeError = InvalidOutPointBytes;
    type Serialized = Vec<u8>;

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        Ok(serialize_outpoints(&self.0))
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        Ok(Self(deserialize_outpoints(bytes)?))
    }
}

/// ZST for withdrawal-funding rows.
#[derive(Debug)]
pub struct WithdrawalFundingRowSpec;

impl KVRowSpec for WithdrawalFundingRowSpec {
    type Key = WithdrawalFundingKey;
    type Value = WithdrawalFundingValue;
}
