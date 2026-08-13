//! Operator wallet — composition over a swappable [`GeneralWallet`] backend.
//!
//! Callers hold an `OperatorWallet<G, P>` where `G: GeneralWallet` and `P: WalletStore`. The
//! composer owns:
//! - a descriptor-only reserved wallet (BDK), signed downstream by the caller and persisted through
//!   `P`,
//! - the in-memory lease set shared across both wallets,
//! - CPFP-anchor identification and exclusion from input selection,
//! - cross-wallet construction helpers that pay from the general wallet into reserved-wallet
//!   outputs of a caller-specified denomination.
//!
//! The [`GeneralWallet`] backend handles only what varies between implementations: its own
//! UTXO discovery, its own signing, and the funding+CPFP construction primitives.
//!
//! Chain state for both wallets is persisted incrementally during sync (see [`persist`]) so a
//! restart resumes from the last committed checkpoint instead of rescanning from genesis.
//!
//! Methods on [`OperatorWallet`] are `&mut self`. Callers serialize via an outer lock when
//! they need a multi-step critical section (e.g. DB-lookup-then-fund-then-persist).

pub mod config;
pub mod general;
pub mod leases;
pub mod persist;
pub mod sync;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
pub mod wallet;

// Dev-deps only used by the `tests/` integration tests; silence the lib-test build's
// unused-crate-dependencies warning.
#[cfg(test)]
use corepc_node as _;
#[cfg(test)]
use operator_wallet as _;
#[cfg(test)]
use serial_test as _;
use thiserror::Error;

pub use crate::{
    config::{OperatorWalletConfig, DEFAULT_PERSIST_EVERY_BLOCKS},
    general::{
        native::NativeGeneralWallet, AnchorInfo, AnchorOwnership, FundedPsbt, GeneralWallet,
        ReplacedChild, UtxoInfo,
    },
    leases::{Lease, LeaseOwner, LeaseSet},
    persist::{
        load_or_create, BlockId, InitError, SqliteStore, SqliteStoreError, WalletKind, WalletStore,
    },
    sync::SyncError,
    wallet::{GeneralUtxoPolicy, LeasedPsbt, OperatorWallet},
};

/// Whether an error describes a condition that a later attempt can pass.
///
/// A caller that retries on a timer needs this. An error about the shape of a transaction
/// that is already signed repeats on every attempt, and a caller that cannot tell the two
/// apart retries that one for as long as the process runs.
pub trait ErrorPermanence {
    /// True when every later attempt against the same inputs fails the same way.
    fn is_permanent(&self) -> bool;
}

/// Errors returned by [`OperatorWallet`] methods. Backend errors are boxed so call sites don't
/// have to be generic over `G::Error`.
#[derive(Debug, Error)]
pub enum Error {
    /// The general wallet backend reported an error.
    #[error("general wallet: {source}")]
    General {
        /// The backend error.
        source: Box<dyn std::error::Error + Send + Sync>,
        /// Read from the backend error before the box hid its type.
        permanent: bool,
    },
    /// Confirmed-only reserved-wallet funding can see only unconfirmed general-wallet funds.
    #[error(
        "no confirmed general-wallet UTXOs available for reserved-wallet funding \
         ({unconfirmed_count} unconfirmed UTXOs totaling {unconfirmed_amount})"
    )]
    NoConfirmedGeneralUtxos {
        /// Number of unconfirmed candidate UTXOs after normal exclusions.
        unconfirmed_count: usize,
        /// Total value of unconfirmed candidate UTXOs after normal exclusions.
        unconfirmed_amount: bdk_wallet::bitcoin::Amount,
    },
    /// No eligible general-wallet inputs have reached the required burial depth.
    #[error("no general-wallet UTXOs buried beyond depth {bury_depth} available for reserved-wallet funding")]
    NoBuriedGeneralUtxos {
        /// Required number of blocks on top of each input transaction.
        bury_depth: u32,
    },
    /// The wallet receive script cannot be represented as a Bitcoin address.
    #[error("wallet receive script is not addressable: {0}")]
    Address(#[from] bdk_wallet::bitcoin::address::FromScriptError),
    /// The wallet address cannot be represented as a BOSD descriptor.
    #[error("wallet address cannot be converted into a descriptor: {0}")]
    Descriptor(#[from] bitcoin_bosd::DescriptorError),
    /// BDK reported an error building a transaction on the reserved wallet.
    #[error("reserved wallet create-tx: {0}")]
    Reserved(#[from] bdk_wallet::error::CreateTxError),
    /// Reserved-wallet sync against the chain failed.
    #[error("reserved wallet sync: {0:?}")]
    Sync(SyncError),
    /// The reserved wallet could not be loaded from or created in its store.
    #[error("reserved wallet init: {0}")]
    ReservedInit(Box<dyn std::error::Error + Send + Sync>),
}

impl Error {
    pub(crate) fn from_general<E>(e: E) -> Self
    where
        E: std::error::Error + ErrorPermanence + Send + Sync + 'static,
    {
        // Read the classification here. The box that follows hides the concrete type, and no
        // later caller can recover it.
        let permanent = e.is_permanent();
        Self::General {
            source: Box::new(e),
            permanent,
        }
    }
}

impl ErrorPermanence for Error {
    fn is_permanent(&self) -> bool {
        match self {
            Self::General { permanent, .. } => *permanent,
            // A missing confirmed or buried UTXO, a failed sync, and a rejected build all pass
            // once the wallet or the chain moves on.
            Self::NoConfirmedGeneralUtxos { .. }
            | Self::NoBuriedGeneralUtxos { .. }
            | Self::Reserved(_)
            | Self::Sync(_) => false,
            // A script that is not addressable, an address that is not a descriptor, and a
            // reserved wallet that its store cannot supply, are properties of the configured
            // wallet. The init failure only occurs while the wallet is built, before any
            // engine boundary can see it.
            Self::Address(_) | Self::Descriptor(_) | Self::ReservedInit(_) => true,
        }
    }
}
