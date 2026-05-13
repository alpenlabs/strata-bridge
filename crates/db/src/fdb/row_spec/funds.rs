//! Row specs for claim-funding, stake-funding, and withdrawal-funding rows.

use std::convert::Infallible;

use bitcoin::{
    OutPoint, Transaction, TxOut, Txid,
    consensus::{Decodable, Encodable, encode},
    hashes::Hash,
};
use foundationdb::tuple::PackError;
use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};

use super::kv::{KVRowSpec, PackableKey, SerializableValue};
use crate::{fdb::dirs::Directories, types::StakeFundingReservation};

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

/// Key for stake-funding rows: `OperatorIdx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeFundingKey {
    /// Operator index.
    pub operator_idx: OperatorIdx,
}

impl PackableKey for StakeFundingKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs.stake_funds.pack::<(u32,)>(&(self.operator_idx,)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (operator_idx,) = dirs.stake_funds.unpack::<(u32,)>(bytes)?;
        Ok(Self { operator_idx })
    }
}

/// Value for a stake-funding row: a single `OutPoint`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeFundingValue(pub OutPoint);

impl SerializableValue for StakeFundingValue {
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
        Ok(Self(outpoints[0]))
    }
}

/// ZST for stake-funding rows.
#[derive(Debug)]
pub struct StakeFundingRowSpec;

impl KVRowSpec for StakeFundingRowSpec {
    type Key = StakeFundingKey;
    type Value = StakeFundingValue;
}

/// Key for stake-funding reservation rows: `OperatorIdx`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeFundingReservationKey {
    /// Operator index.
    pub operator_idx: OperatorIdx,
}

impl PackableKey for StakeFundingReservationKey {
    type PackingError = Infallible;
    type UnpackingError = PackError;
    type Packed = Vec<u8>;

    fn pack(&self, dirs: &Directories) -> Result<Self::Packed, Self::PackingError> {
        Ok(dirs
            .stake_funding_reservations
            .pack::<(u32,)>(&(self.operator_idx,)))
    }

    fn unpack(dirs: &Directories, bytes: &[u8]) -> Result<Self, Self::UnpackingError> {
        let (operator_idx,) = dirs.stake_funding_reservations.unpack::<(u32,)>(bytes)?;
        Ok(Self { operator_idx })
    }
}

/// Error returned when a stake-funding reservation's bytes cannot be parsed.
#[derive(Debug)]
pub enum InvalidStakeFundingReservationBytes {
    /// The byte slice ended before all fields were read.
    UnexpectedEof,
    /// A consensus-encoded field failed to decode.
    Decode(encode::Error),
    /// Bytes past the encoded reservation were not consumed.
    TrailingBytes,
}

impl From<encode::Error> for InvalidStakeFundingReservationBytes {
    fn from(err: encode::Error) -> Self {
        Self::Decode(err)
    }
}

/// Value for a stake-funding reservation row: a [`StakeFundingReservation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakeFundingReservationValue(pub StakeFundingReservation);

impl SerializableValue for StakeFundingReservationValue {
    type SerializeError = Infallible;
    type DeserializeError = InvalidStakeFundingReservationBytes;
    type Serialized = Vec<u8>;

    fn serialize(&self) -> Result<Self::Serialized, Self::SerializeError> {
        let reservation = &self.0;
        let mut buf = Vec::new();
        buf.extend_from_slice(&reservation.stake_output_vout.to_le_bytes());
        // `Transaction` and `Vec<TxOut>` are length-prefixed by their own consensus encoding,
        // so concatenation is unambiguous.
        reservation
            .unsigned_tx
            .consensus_encode(&mut buf)
            .expect("writing to Vec<u8> is infallible");
        reservation
            .prevouts
            .consensus_encode(&mut buf)
            .expect("writing to Vec<u8> is infallible");
        Ok(buf)
    }

    fn deserialize(bytes: &[u8]) -> Result<Self, Self::DeserializeError> {
        if bytes.len() < SERIALIZED_VOUT_SIZE {
            return Err(InvalidStakeFundingReservationBytes::UnexpectedEof);
        }
        let (vout_bytes, mut rest) = bytes.split_at(SERIALIZED_VOUT_SIZE);
        let stake_output_vout = u32::from_le_bytes(
            vout_bytes
                .try_into()
                .expect("split_at guarantees length matches"),
        );
        let unsigned_tx = Transaction::consensus_decode(&mut rest)?;
        let prevouts = Vec::<TxOut>::consensus_decode(&mut rest)?;
        if !rest.is_empty() {
            return Err(InvalidStakeFundingReservationBytes::TrailingBytes);
        }
        Ok(Self(StakeFundingReservation {
            unsigned_tx,
            prevouts,
            stake_output_vout,
        }))
    }
}

/// ZST for stake-funding reservation rows.
#[derive(Debug)]
pub struct StakeFundingReservationRowSpec;

impl KVRowSpec for StakeFundingReservationRowSpec {
    type Key = StakeFundingReservationKey;
    type Value = StakeFundingReservationValue;
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

#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::bitcoin::generate_tx;

    use super::*;

    fn sample_reservation(n_inputs: usize) -> StakeFundingReservation {
        let unsigned_tx = generate_tx(n_inputs, 1);
        let prevouts = unsigned_tx.output.clone();
        StakeFundingReservation {
            unsigned_tx,
            prevouts,
            stake_output_vout: 0,
        }
    }

    #[test]
    fn reservation_single_input_roundtrip() {
        let reservation = sample_reservation(1);
        let value = StakeFundingReservationValue(reservation.clone());
        let bytes = value.serialize().unwrap();
        let decoded = StakeFundingReservationValue::deserialize(bytes.as_ref()).unwrap();
        assert_eq!(
            decoded.0, reservation,
            "decoded reservation must match the original"
        );
    }

    #[test]
    fn reservation_multi_input_roundtrip() {
        let reservation = sample_reservation(3);
        let value = StakeFundingReservationValue(reservation.clone());
        let bytes = value.serialize().unwrap();
        let decoded = StakeFundingReservationValue::deserialize(bytes.as_ref()).unwrap();
        assert_eq!(
            decoded.0, reservation,
            "multi-input reservation must round-trip"
        );
    }

    #[test]
    fn reservation_deserialize_empty_bytes_errors() {
        let err = StakeFundingReservationValue::deserialize(&[]).unwrap_err();
        assert!(
            matches!(err, InvalidStakeFundingReservationBytes::UnexpectedEof),
            "empty bytes must be rejected as UnexpectedEof",
        );
    }

    #[test]
    fn reservation_deserialize_trailing_bytes_errors() {
        let reservation = sample_reservation(1);
        let value = StakeFundingReservationValue(reservation);
        let mut bytes = value.serialize().unwrap();
        bytes.push(0x42);
        let err = StakeFundingReservationValue::deserialize(&bytes).unwrap_err();
        assert!(
            matches!(err, InvalidStakeFundingReservationBytes::TrailingBytes),
            "trailing bytes after a valid reservation must be rejected",
        );
    }

    #[test]
    fn reservation_deserialize_truncated_errors() {
        let reservation = sample_reservation(2);
        let value = StakeFundingReservationValue(reservation);
        let bytes = value.serialize().unwrap();
        let err = StakeFundingReservationValue::deserialize(&bytes[..bytes.len() - 1]).unwrap_err();
        assert!(
            matches!(err, InvalidStakeFundingReservationBytes::Decode(_)),
            "truncated bytes must surface a consensus decode error, got {err:?}",
        );
    }
}
