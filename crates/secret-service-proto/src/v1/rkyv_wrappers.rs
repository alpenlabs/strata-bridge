//! This module contains rkyv wrappers for various remote types.
//!
//! These are not intended to be used directly and therefore have no documentation.
//!
//! These are intended to be used with `#[rkyv(with = ...)]` to allow rkyv to serialize and
//! deserialize these remote types.

use bitcoin::hashes::Hash as _;
use rkyv::{Archive, Deserialize, Serialize};

/// Wrapper for [`musig2::errors::RoundContributionError`].
#[derive(Debug, PartialEq, Eq, Clone, Archive, Serialize, Deserialize)]
#[rkyv(remote = musig2::errors::RoundContributionError)]
#[rkyv(archived = ArchivedRoundContributionError)]
pub struct RoundContributionError {
    /// The index of the contributor.
    pub index: usize,

    /// The reason for the error.
    #[rkyv(with = ContributionFaultReason)]
    pub reason: musig2::errors::ContributionFaultReason,
}

impl From<musig2::errors::RoundContributionError> for RoundContributionError {
    fn from(value: musig2::errors::RoundContributionError) -> Self {
        Self {
            index: value.index,
            reason: value.reason,
        }
    }
}

impl From<RoundContributionError> for musig2::errors::RoundContributionError {
    fn from(value: RoundContributionError) -> Self {
        Self {
            index: value.index,
            reason: value.reason,
        }
    }
}

/// Wrapper for [`musig2::errors::ContributionFaultReason`].
#[derive(Debug, PartialEq, Eq, Clone, Archive, Serialize, Deserialize)]
#[rkyv(remote = musig2::errors::ContributionFaultReason)]
#[rkyv(archived = ArchivedContributionFaultReason)]
pub enum ContributionFaultReason {
    /// The index is out of range.
    OutOfRange(usize),

    /// The contribution is inconsistent.
    InconsistentContribution,

    /// The signature is invalid.
    InvalidSignature,
}

impl From<musig2::errors::ContributionFaultReason> for ContributionFaultReason {
    fn from(value: musig2::errors::ContributionFaultReason) -> Self {
        match value {
            musig2::errors::ContributionFaultReason::OutOfRange(v) => Self::OutOfRange(v),
            musig2::errors::ContributionFaultReason::InconsistentContribution => {
                Self::InconsistentContribution
            }
            musig2::errors::ContributionFaultReason::InvalidSignature => Self::InvalidSignature,
        }
    }
}

impl From<ContributionFaultReason> for musig2::errors::ContributionFaultReason {
    fn from(value: ContributionFaultReason) -> Self {
        match value {
            ContributionFaultReason::OutOfRange(v) => Self::OutOfRange(v),
            ContributionFaultReason::InconsistentContribution => Self::InconsistentContribution,
            ContributionFaultReason::InvalidSignature => Self::InvalidSignature,
        }
    }
}

/// Wrapper for [`musig2::errors::RoundFinalizeError`].
#[derive(Debug, PartialEq, Eq, Clone, Archive, Serialize, Deserialize)]
#[rkyv(remote = musig2::errors::RoundFinalizeError)]
#[rkyv(archived = ArchivedRoundFinalizeError)]
pub enum RoundFinalizeError {
    /// The round was not completed.
    Incomplete,

    /// Wrapper for [`musig2::errors::SigningError`].
    SigningError(#[rkyv(with = SigningError)] musig2::errors::SigningError),

    /// Wrapper for [`musig2::errors::VerifyError`].
    InvalidAggregatedSignature(#[rkyv(with = VerifyError)] musig2::errors::VerifyError),
}

impl From<musig2::errors::RoundFinalizeError> for RoundFinalizeError {
    fn from(value: musig2::errors::RoundFinalizeError) -> Self {
        match value {
            musig2::errors::RoundFinalizeError::Incomplete => Self::Incomplete,
            musig2::errors::RoundFinalizeError::SigningError(v) => Self::SigningError(v),
            musig2::errors::RoundFinalizeError::InvalidAggregatedSignature(v) => {
                Self::InvalidAggregatedSignature(v)
            }
        }
    }
}

impl From<RoundFinalizeError> for musig2::errors::RoundFinalizeError {
    fn from(value: RoundFinalizeError) -> Self {
        match value {
            RoundFinalizeError::Incomplete => musig2::errors::RoundFinalizeError::Incomplete,
            RoundFinalizeError::SigningError(v) => {
                musig2::errors::RoundFinalizeError::SigningError(v)
            }
            RoundFinalizeError::InvalidAggregatedSignature(v) => {
                musig2::errors::RoundFinalizeError::InvalidAggregatedSignature(v)
            }
        }
    }
}

/// Wrapper for [`musig2::errors::SigningError`].
#[derive(Debug, PartialEq, Eq, Clone, Archive, Serialize, Deserialize)]
#[rkyv(remote = musig2::errors::SigningError)]
#[rkyv(archived = ArchivedSigningError)]
pub enum SigningError {
    /// Unknown key.
    UnknownKey,

    /// Self verification failed.
    SelfVerifyFail,
}

impl From<musig2::errors::SigningError> for SigningError {
    fn from(value: musig2::errors::SigningError) -> Self {
        match value {
            musig2::errors::SigningError::UnknownKey => Self::UnknownKey,
            musig2::errors::SigningError::SelfVerifyFail => Self::SelfVerifyFail,
        }
    }
}

impl From<SigningError> for musig2::errors::SigningError {
    fn from(value: SigningError) -> Self {
        match value {
            SigningError::UnknownKey => musig2::errors::SigningError::UnknownKey,
            SigningError::SelfVerifyFail => musig2::errors::SigningError::SelfVerifyFail,
        }
    }
}

/// Wrapper for [`musig2::errors::VerifyError`].
#[derive(Debug, PartialEq, Eq, Clone, Archive, Serialize, Deserialize)]
#[rkyv(remote = musig2::errors::VerifyError)]
#[rkyv(archived = ArchivedVerifyError)]
pub enum VerifyError {
    /// Unknown key.
    UnknownKey,

    /// Bad signature.
    BadSignature,
}

impl From<musig2::errors::VerifyError> for VerifyError {
    fn from(value: musig2::errors::VerifyError) -> Self {
        match value {
            musig2::errors::VerifyError::UnknownKey => Self::UnknownKey,
            musig2::errors::VerifyError::BadSignature => Self::BadSignature,
        }
    }
}

impl From<VerifyError> for musig2::errors::VerifyError {
    fn from(value: VerifyError) -> Self {
        match value {
            VerifyError::UnknownKey => musig2::errors::VerifyError::UnknownKey,
            VerifyError::BadSignature => musig2::errors::VerifyError::BadSignature,
        }
    }
}

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
