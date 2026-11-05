//! Operator wallet — general funds and reserved funds behind one composer.
//!
//! Callers hold an `OperatorWallet<P>` where `P: WalletStore`. The composer owns:
//! - a descriptor-only general wallet, and the [`GeneralSigner`](general::GeneralSigner) that
//!   [`GeneralCustody`] chose for it,
//! - a descriptor-only reserved wallet (BDK), signed downstream by the caller and persisted through
//!   `P`,
//! - the in-memory lease set shared across both wallets,
//! - CPFP-anchor identification and exclusion from input selection,
//! - cross-wallet construction helpers that pay from the general wallet into reserved-wallet
//!   outputs of a caller-specified denomination.
//!
//! Chain state for both wallets is persisted incrementally during sync (see [`persist`]) so a
//! restart resumes from the last committed checkpoint instead of rescanning from genesis.
//!
//! Selection methods on [`OperatorWallet`] are synchronous and take `&mut self`, and the caller
//! signs afterwards with no wallet lock held. See [`wallet`] for why.

pub mod config;
pub mod general;
#[allow(dead_code)]
pub mod leases;
pub mod persist;
#[allow(dead_code)]
mod plan;
pub mod sync;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;
mod tracked;
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
    config::{
        OperatorWalletConfig, DEFAULT_PERSIST_EVERY_BLOCKS, DEFAULT_SYNC_BACKOFF,
        DEFAULT_SYNC_BASE_DELAY, DEFAULT_SYNC_RETRIES,
    },
    general::GeneralCustody,
    leases::{Lease, LeaseOwner},
    persist::{
        load_or_create, BlockId, InitError, SqliteStore, SqliteStoreError, WalletKind, WalletStore,
    },
    plan::{FundingInput, IncumbentChild, REPLACEMENT_INCREMENT_SAT_PER_VB},
    sync::SyncError,
    tracked::{TrackedWallet, UtxoInfo},
    wallet::{GeneralUtxoPolicy, LastSync, LeasedPsbt, OperatorWallet},
};

/// Errors returned by [`OperatorWallet`] methods. An init error is boxed so that call sites do not
/// have to be generic over `P::Error`.
#[derive(Debug, Error)]
pub enum Error {
    /// The general wallet could not sync.
    #[error("general wallet sync: {0:?}")]
    GeneralSync(SyncError),
    /// The inputs that selection reached cannot pay for the transaction.
    #[error("insufficient funds: {available} available, {needed} needed")]
    InsufficientFunds {
        /// Value of the inputs that selection reached.
        available: bdk_wallet::bitcoin::Amount,
        /// Value those inputs must reach for the transaction to work.
        needed: bdk_wallet::bitcoin::Amount,
    },
    /// Reserved-wallet funding found only unconfirmed general-wallet inputs, and the policy
    /// excludes them.
    #[error(
        "no confirmed general-wallet UTXOs available; {unconfirmed_count} unconfirmed UTXOs worth {unconfirmed_amount} were skipped"
    )]
    NoConfirmedGeneralUtxos {
        /// Number of unconfirmed candidate UTXOs after normal exclusions.
        unconfirmed_count: usize,
        /// Total value of unconfirmed candidate UTXOs after normal exclusions.
        unconfirmed_amount: bdk_wallet::bitcoin::Amount,
    },
    /// No eligible general-wallet inputs have reached the required burial depth.
    #[error("no general-wallet UTXOs buried beyond depth {bury_depth} available")]
    NoBuriedGeneralUtxos {
        /// Required number of blocks on top of each input transaction.
        bury_depth: u32,
    },
    /// An explicitly named input is not a spendable output of the general wallet.
    #[error("input {0} is not a spendable general-wallet output")]
    UnknownInput(bdk_wallet::bitcoin::OutPoint),
    /// The wallet receive script cannot be represented as a Bitcoin address.
    #[error("wallet receive script is not addressable: {0}")]
    Address(#[from] bdk_wallet::bitcoin::address::FromScriptError),
    /// The wallet address cannot be represented as a BOSD descriptor.
    #[error("wallet address cannot be converted into a descriptor: {0}")]
    Descriptor(#[from] bitcoin_bosd::DescriptorError),
    /// The reserved wallet could not sync.
    #[error("reserved wallet sync: {0:?}")]
    ReservedSync(SyncError),
    /// The general wallet could not be loaded from or created in its store.
    #[error("general wallet init: {0}")]
    GeneralInit(Box<dyn std::error::Error + Send + Sync>),
    /// The reserved wallet could not be loaded from or created in its store.
    #[error("reserved wallet init: {0}")]
    ReservedInit(Box<dyn std::error::Error + Send + Sync>),
}

impl From<plan::Shortfall> for Error {
    fn from(shortfall: plan::Shortfall) -> Self {
        Self::InsufficientFunds {
            available: shortfall.available,
            needed: shortfall.needed,
        }
    }
}
