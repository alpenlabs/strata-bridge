/// Represents all errors that can occur during verification of a bridge proof.
#[derive(Debug, thiserror::Error)]
pub enum BridgeProofError {
    /// The checkpoint extraction failed or was missing.
    #[error("Could not extract checkpoint: {0}")]
    CheckpointExtractionError(String),

    /// The checkpoint transaction proof is invalid or missing from the headers.
    #[error("Invalid checkpoint transaction inclusion proof.")]
    InvalidCheckpointTxInclusion,

    /// The chain state root does not match the checkpoint's state root.
    #[error("Mismatch between chain state root and checkpoint state root.")]
    InvalidChainStateRoot,

    /// A header in the provided list of headers is invalid or out of continuity.
    #[error("Failed to verify continuity for one or more headers.")]
    InvalidHeaderContinuity,

    /// The withdrawal fulfillment transaction proof is invalid or missing from the headers.
    #[error("Invalid withdrawal fulfillment transaction inclusion proof.")]
    InvalidWithdrawalFulfillmentInclusion,

    /// The chain state does not match the expected deposit or withdrawal data.
    #[error("Mismatch in operator index, withdrawal address, or amount.")]
    InvalidWithdrawalData,

    /// The anchor public key merkle proof is invalid or missing.
    #[error("Invalid anchor public key merkle proof.")]
    InvalidAnchorProof,

    /// The claim transaction proof is invalid or missing from the headers.
    #[error("Invalid claim transaction inclusion proof.")]
    InvalidClaimTxInclusion,

    /// The claim transaction does not commit to the correct withdrawal fulfillment TxID.
    #[error("Invalid claim transaction: withdrawal fulfillment TxID mismatch.")]
    InvalidClaimTxFulfillment,

    /// The claim transaction does not commit to the correct anchor public key index.
    #[error("Invalid claim transaction: anchor index mismatch.")]
    InvalidClaimTxAnchorIndex,

    /// A generic error occurred (wraps a string message).
    #[error("{0}")]
    Generic(String),
}
