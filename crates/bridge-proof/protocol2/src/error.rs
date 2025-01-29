use thiserror::Error;

/// Represents all possible errors that can occur during the verification of a bridge proof.
#[derive(Error, Debug)]
pub(crate) enum BridgeProofError {
    /// Error extracting transaction-related information.
    /// Contains the specific transaction type that triggered the error.
    #[error("Could not extract info from tx: {0:?}")]
    TxInfoExtractionError(BridgeRelatedTx),

    /// The merkle proof for the transaction is invalid.
    /// Contains the specific transaction type that triggered the error.
    #[error("Merkle inclusion proof invalid for tx: {0:?}")]
    InvalidMerkleProof(BridgeRelatedTx),

    /// The chain state root does not match the checkpoint's state root.
    #[error("Mismatch between input ChainState and CheckpointTx ChainState")]
    ChainStateMismatch,

    /// The chain state has encountered an internal error that is derived from `ChainStateError`.
    #[error("Mismatch between input ChainState and CheckpointTx ChainState")]
    ChainStateError(#[from] ChainStateError),

    /// The chain state does not match the expected deposit or withdrawal data,
    /// such as operator index, withdrawal address, or amount.
    #[error("Mismatch in operator index, withdrawal address, or amount.")]
    InvalidWithdrawalData,

    /// The claim transaction's information is invalid, for instance a withdrawal commitment
    /// mismatch.
    #[error("Claim info is invalid")]
    InvalidClaimInfo(#[from] InvalidClaimInfo),

    /// The operator's signature is invalid
    #[error("Signature is invalid")]
    InvalidSignature,

    /// The operator's fulfilled the withdrawal request after the deadline
    #[error("Withdrawal fulfilled after deadline exceeded")]
    DeadlineExceeded,

    /// The transactions are not ordered as expected
    #[error("Invalid transactions order. {0:?} must occur before {1:?}")]
    InvalidTxOrder(BridgeRelatedTx, BridgeRelatedTx),
}

/// Represents all errors that can occur specifically during the verification of a claim's
/// information.
#[derive(Debug, Error)]
pub(crate) enum InvalidClaimInfo {
    /// Indicates that the withdrawal fulfillment transaction ID committed on-chain
    /// was not found or did not match the expected one in the provided header chain.
    #[error("Committed withdrawal fulfillment transaction ID not found in the header chain")]
    InvalidWithdrawalCommitment,
}

/// Represents errors that occur during the verification of chain state.
#[derive(Debug, Error)]
pub(crate) enum ChainStateError {
    /// Indicates that the deposit could not be found for the specified index.
    #[error("Deposit not found for idx {0}")]
    DepositNotFound(u32),

    /// Indicates that the deposit state is invalid or unexpected for the operation in question.
    #[error("Deposit state is expected to be Dispatched")]
    InvalidDepositState,
}

/// Identifies the type of a transaction relevant to the bridge proof process.
#[derive(Debug, Clone)]
pub(crate) enum BridgeRelatedTx {
    /// A Strata checkpoint transaction.
    StrataCheckpoint,
    /// A withdrawal fulfillment transaction.
    WithdrawalFulfillment,
    /// A claim transaction.
    Claim,
}
