//! Errors raised when verifying a bridge proof claim.

use strata_codec::CodecError;
use strata_predicate::PredicateError;
use thiserror::Error;

/// Errors that can occur while verifying a [`BridgeProofInput`](crate::BridgeProofInput).
#[derive(Debug, Error)]
pub enum BridgeProofVerificationError {
    /// The recursive Moho proof failed predicate verification.
    #[error("invalid moho proof: {0}")]
    InvalidMohoProof(#[source] PredicateError),

    /// The bridge-v1 export container is not present in the Moho state.
    #[error("bridge-v1 export container missing from moho state")]
    MissingBridgeContainer,

    /// `claim_unlock` is not committed to the bridge-v1 export-entries MMR.
    #[error("claim unlock not included in bridge-v1 export-entries MMR")]
    InvalidInclusionProof,

    /// The Codec-encoded `OperatorClaimUnlock` bytes did not decode.
    #[error("invalid claim_unlock encoding: {0}")]
    InvalidClaimUnlock(#[source] CodecError),
}
