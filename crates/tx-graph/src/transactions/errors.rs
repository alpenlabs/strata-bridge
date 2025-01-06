use bitcoin::taproot::TaprootBuilderError;
use thiserror::Error;

#[derive(Debug, Clone, Error)]
pub enum TxError {
    /// Error due to there being no script provided to create a taproot address.
    #[error("noscript taproot address for only script path spend is not possible")]
    EmptyTapscript,

    /// Error while building the taproot address.
    #[error("could not build taproot address: {0}")]
    BuildFailed(#[from] TaprootBuilderError),

    /// Error while adding a leaf to to a [`TaprootBuilder`].
    #[error("could not add leaf to the taproot tree")]
    CouldNotAddLeaf,

    /// Could not create psbt from the unsigned transaction.
    #[error("problem with psbt due to: {0}")]
    PsbtCreate(String),

    /// An unexpected error occurred.
    // HACK: This should only be used while developing, testing or bikeshedding the right variant
    // for a particular error.
    #[error("unexpected error occurred: {0}")]
    Unexpected(String),
}

pub type TxResult<T> = Result<T, TxError>;
