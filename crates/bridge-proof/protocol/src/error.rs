use strata_asm_types::L1VerificationError;
use thiserror::Error;

/// Represents all possible errors that can occur during the verification of a bridge proof.
#[derive(Error, Debug)]
pub(crate) enum BridgeProofError {
    /// The rollup params are invalid.
    #[error("invalid rollup params: {0}")]
    InvalidParams(String),

    /// Error extracting transaction-related information.
    /// Contains the specific transaction type that triggered the error.
    #[error("Could not extract info from tx: {0:?}")]
    TxInfoExtractionError(BridgeRelatedTx),

    /// The merkle proof for the transaction is invalid.
    /// Contains the specific transaction type that triggered the error.
    #[error("Merkle inclusion proof invalid for tx: {0:?}")]
    InvalidMerkleProof(BridgeRelatedTx),

    /// The chain state root does not match the checkpoint's state root.
    #[error("Mismatch between ChainState in Checkpoint Sidecar and CheckpointTx transition proof")]
    ChainStateMismatch,

    /// The chain state has encountered an internal error that is derived from `ChainStateError`.
    #[error("Mismatch between input ChainState and CheckpointTx ChainState")]
    ChainStateError(#[from] ChainStateError),

    /// The chain state does not match the expected deposit or withdrawal data,
    /// such as operator index, withdrawal address, or amount.
    #[error("Mismatch in operator index, withdrawal address, or amount.")]
    InvalidWithdrawalData,

    /// The operator's signature is invalid
    #[error("Operator's signature is invalid")]
    InvalidOperatorSignature,

    /// Strata's credential rule is not satisfied
    #[error("Strata's Credential Rule is not satisfied")]
    UnsatisfiedStrataCredRule,

    /// Strata's Proof in Checkpoint Transaction is invalid
    #[error("Strata proof in checkpoint transaction is invalid")]
    InvalidStrataProof,

    /// The operator's fulfilled the withdrawal request after the deadline
    #[error("Withdrawal fulfilled after deadline exceeded")]
    DeadlineExceeded,

    /// The transactions are not ordered as expected
    #[error("Invalid transactions order. {0:?} must occur before {1:?}")]
    InvalidTxOrder(BridgeRelatedTx, BridgeRelatedTx),

    /// Insufficient blocks submitted after the withdrawal fulfillment transaction.
    #[error("Expected at least {0} blocks after the withdrawal fulfillment transaction, but {1} were provided.")]
    InsufficientBlocksAfterWithdrawalFulfillment(usize, usize),

    /// Provided header does not follow consensus rules
    #[error("Invalid header")]
    InvalidHeader(#[from] L1VerificationError),
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

    /// The deposit TxId recorded in the chainstate does not match the txid referenced in the
    /// WithdrawalFulfillmentTx.
    #[error(
        "Mismatched deposit txid: chainstate has {deposit_txid_in_chainstate}, but fulfillment has {deposit_txid_in_fulfillment}"
    )]
    MismatchedDepositTxid {
        deposit_txid_in_chainstate: bitcoin::Txid,
        deposit_txid_in_fulfillment: bitcoin::Txid,
    },
}

/// Identifies the type of a transaction relevant to the bridge proof process.
#[derive(Debug, Clone)]
pub(crate) enum BridgeRelatedTx {
    /// A Strata checkpoint transaction.
    StrataCheckpoint,
    /// A withdrawal fulfillment transaction.
    #[expect(dead_code)]
    WithdrawalFulfillment(String),
}
