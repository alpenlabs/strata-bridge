//! This module contains rkyv wrappers for various remote types.
//!
//! These are not intended to be used directly and therefore have no documentation.
//!
//! These are intended to be used with `#[rkyv(with = ...)]` to allow rkyv to serialize and
//! deserialize these remote types.

use rkyv::{Archive, Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, Clone, Archive, Serialize, Deserialize)]
#[rkyv(remote = musig2::errors::RoundContributionError)]
#[rkyv(archived = ArchivedRoundContributionError)]
pub struct RoundContributionError {
    pub index: usize,

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

#[derive(Debug, PartialEq, Eq, Clone, Archive, Serialize, Deserialize)]
#[rkyv(remote = musig2::errors::ContributionFaultReason)]
#[rkyv(archived = ArchivedContributionFaultReason)]
pub enum ContributionFaultReason {
    OutOfRange(usize),
    InconsistentContribution,
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

#[derive(Debug, PartialEq, Eq, Clone, Archive, Serialize, Deserialize)]
#[rkyv(remote = musig2::errors::RoundFinalizeError)]
#[rkyv(archived = ArchivedRoundFinalizeError)]
pub enum RoundFinalizeError {
    Incomplete,
    SigningError(#[rkyv(with = SigningError)] musig2::errors::SigningError),
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

#[derive(Debug, PartialEq, Eq, Clone, Archive, Serialize, Deserialize)]
#[rkyv(remote = musig2::errors::SigningError)]
#[rkyv(archived = ArchivedSigningError)]
pub enum SigningError {
    UnknownKey,
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

#[derive(Debug, PartialEq, Eq, Clone, Archive, Serialize, Deserialize)]
#[rkyv(remote = musig2::errors::VerifyError)]
#[rkyv(archived = ArchivedVerifyError)]
pub enum VerifyError {
    UnknownKey,
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
