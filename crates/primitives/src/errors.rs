//! Enumerated errors related to creation and signing of bridge-related transactions.

use bitcoin::{
    address, psbt,
    taproot::{TaprootBuilder, TaprootBuilderError},
    AddressType,
};
use thiserror::Error;

use crate::types::OperatorIdx;

/// Error during building of bridge-related transactions.
#[derive(Debug, Error)]
pub enum BridgeTxBuilderError {
    /// Error building the Deposit Transaction.
    #[error("could not build deposit transaction: {0}")]
    DepositTransaction(#[from] DepositTransactionError),

    /// Error building the Deposit Transaction.
    #[error("could not build cooperative withdrawal transaction: {0}")]
    CooperativeWithdrawalTransaction(#[from] CooperativeWithdrawalError),

    /// Error due to there being no script provided to create a taproot address.
    #[error("noscript taproot address for only script path spend is not possible")]
    EmptyTapscript,

    /// Error while building the taproot address.
    #[error("could not build taproot address: {0}")]
    BuildFailed(#[from] TaprootBuilderError),

    /// Error while adding a leaf to to a [`TaprootBuilder`].
    #[error("could not add leaf to the taproot tree")]
    CouldNotAddLeaf,

    /// An unexpected error occurred.
    // HACK: This should only be used while developing, testing or bikeshedding the right variant
    // for a particular error.
    #[error("unexpected error occurred: {0}")]
    Unexpected(String),

    /// Could not create psbt from the unsigned transaction.
    #[error("problem with psbt due to: {0}")]
    PsbtCreate(String),
}

/// Manual implementation of conversion from [`psbt::Error`] to [`BridgeTxBuilderError`] as the
/// former does not implement [`Clone`] ¯\_(ツ)_/¯.
impl From<psbt::Error> for BridgeTxBuilderError {
    fn from(value: psbt::Error) -> Self {
        Self::PsbtCreate(value.to_string())
    }
}

/// Result type alias that has [`BridgeTxBuilderError`] as the error type for succinctness.
pub type BridgeTxBuilderResult<T> = Result<T, BridgeTxBuilderError>;

/// The unmodified [`TaprootBuilder`] is returned if a leaf could not be added to the taproot in the
/// call to [`TaprootBuilder::add_leaf`].
impl From<TaprootBuilder> for BridgeTxBuilderError {
    fn from(_value: TaprootBuilder) -> Self {
        BridgeTxBuilderError::CouldNotAddLeaf
    }
}

/// Error building the Deposit Transaction.
#[derive(Debug, Error)]
pub enum DepositTransactionError {
    /// Invalid address provided in the Deposit Request Transaction output.
    #[error("invalid deposit request taproot address")]
    InvalidDRTAddress,

    /// Invalid address size provided for the execution environment address where the bridged-in
    /// amount is to be minted.
    #[error("ee size mismatch, got {0} expected {1}")]
    InvalidEeAddressSize(usize, usize),

    /// Error while generating the control block. This mostly means that the control block is
    /// invalid i.e., it does not have the right commitment.
    #[error("control block generation invalid")]
    ControlBlockError,

    /// The provided tapleaf hash (merkle branch) is invalid.
    #[error("invalid merkle proof")]
    InvalidTapLeafHash,
}

/// Error while creating the cooperative withdrawal transaction.
#[derive(Debug, Clone, Error)]
pub enum CooperativeWithdrawalError {
    /// The supplied user x-only-pk for the user requesting the withdrawal is incorrect.
    #[error("the supplied user public key is invalid: {0}")]
    InvalidUserPk(#[from] ParseError),

    /// The supplied assigned operator id is not part of the federation
    #[error("operator idx {0} is not part of federation")]
    Unauthorized(OperatorIdx),
}

#[derive(Debug, Clone, Error)]
pub enum ParseError {
    #[error("supplied pubkey is invalid")]
    InvalidPubkey(#[from] secp256k1::Error),

    #[error("supplied address is invalid")]
    InvalidAddress(#[from] address::ParseError),

    #[error("only taproot addresses are supported but found {0:?}")]
    UnsupportedAddress(Option<AddressType>),

    #[error("not a valid point on the curve: {0:?}")]
    InvalidPoint(Vec<u8>),

    #[error("invalid witness: {0}")]
    InvalidWitness(String),
}

pub type ParseResult<T> = Result<T, ParseError>;
