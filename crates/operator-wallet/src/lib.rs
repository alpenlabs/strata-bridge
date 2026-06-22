//! Operator wallet — composition over a swappable [`GeneralWallet`] backend.
//!
//! Callers hold an `OperatorWallet<G>` where `G: GeneralWallet`. The composer owns:
//! - a descriptor-only reserved wallet (BDK), signed downstream by the caller,
//! - the in-memory lease set shared across both wallets,
//! - CPFP-anchor identification and exclusion from input selection,
//! - cross-wallet construction helpers that pay from the general wallet into reserved-wallet
//!   outputs of a caller-specified denomination.
//!
//! The [`GeneralWallet`] backend handles only what varies between implementations: its own
//! UTXO discovery, its own signing, and the funding+CPFP construction primitives.
//!
//! Methods on [`OperatorWallet`] are `&mut self`. Callers serialize via an outer lock when
//! they need a multi-step critical section (e.g. DB-lookup-then-fund-then-persist).

pub mod config;
pub mod general;
pub mod sync;
pub mod wallet;

// Dev-deps only used by the `tests/` integration tests; silence the lib-test build's
// unused-crate-dependencies warning.
#[cfg(test)]
use corepc_node as _;
#[cfg(test)]
use serial_test as _;
use thiserror::Error;

pub use crate::{
    config::OperatorWalletConfig,
    general::{native::NativeGeneralWallet, AnchorInfo, FundedPsbt, GeneralWallet, UtxoInfo},
    sync::SyncError,
    wallet::OperatorWallet,
};

/// Errors returned by [`OperatorWallet`] methods. Backend errors are boxed so call sites don't
/// have to be generic over `G::Error`.
#[derive(Debug, Error)]
pub enum Error {
    /// The general wallet backend reported an error.
    #[error("general wallet: {0}")]
    General(Box<dyn std::error::Error + Send + Sync>),
    /// BDK reported an error building a transaction on the reserved wallet.
    #[error("reserved wallet create-tx: {0}")]
    Reserved(#[from] bdk_wallet::error::CreateTxError),
    /// Reserved-wallet sync against the chain failed.
    #[error("reserved wallet sync: {0:?}")]
    Sync(SyncError),
}

impl Error {
    pub(crate) fn from_general<E: std::error::Error + Send + Sync + 'static>(e: E) -> Self {
        Self::General(Box::new(e))
    }
}
