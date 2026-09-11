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
pub mod persist;
pub mod sync;
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

#[cfg(any(test, feature = "test-utils"))]
pub use crate::persist::test_utils;
pub use crate::{
    config::{OperatorWalletConfig, DEFAULT_PERSIST_EVERY_BLOCKS},
    general::{native::NativeGeneralWallet, FundedPsbt, GeneralWallet, UtxoInfo},
    persist::{
        load_or_create, BlockId, InitError, SqliteStore, SqliteStoreError, WalletKind, WalletStore,
    },
    sync::SyncError,
    wallet::{GeneralUtxoPolicy, OperatorWallet},
};

/// Errors returned by [`OperatorWallet`] methods. Backend errors are boxed so call sites don't
/// have to be generic over `G::Error`.
#[derive(Debug, Error)]
pub enum Error {
    /// The general wallet backend reported an error.
    #[error("general wallet: {0}")]
    General(Box<dyn std::error::Error + Send + Sync>),
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
    pub(crate) fn from_general<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::General(Box::new(e))
    }
}
