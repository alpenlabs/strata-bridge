//! Configuration knobs for [`crate::OperatorWallet`].
//!
//! Holds runtime parameters that don't change after construction (network, anchor-identification
//! value, sync retry policy). Per-call parameters like UTXO denominations are passed to the
//! relevant methods directly; this struct intentionally does not bake them in so the same
//! composer can serve multiple use cases (claim funding, stake funding, etc.) without
//! conflating their denominations.

use std::time::Duration;

use bdk_wallet::bitcoin::{Amount, Network};

/// How many times wallet sync is reattempted after an error before propagating.
pub const DEFAULT_SYNC_RETRIES: u32 = 5;

/// Exponential backoff base for sync retries: `delay = DEFAULT_SYNC_BASE_DELAY *
/// DEFAULT_SYNC_BACKOFF.pow(attempt)`.
pub const DEFAULT_SYNC_BACKOFF: u32 = 3;

/// Initial delay between sync retry attempts (multiplied by the exponential backoff).
pub const DEFAULT_SYNC_BASE_DELAY: Duration = Duration::from_millis(100);

/// Configuration for [`crate::OperatorWallet`].
#[derive(Debug, Clone)]
pub struct OperatorWalletConfig {
    /// Value that identifies a CPFP anchor output. Outputs with this exact value at zero
    /// confirmations are excluded from input selection so a future CPFP child can spend them.
    pub(crate) cpfp_value: Amount,
    /// Bitcoin network the composed wallets operate on.
    pub(crate) network: Network,
    /// Number of times a wallet sync attempt is retried before propagating the error.
    pub(crate) sync_retries: u32,
    /// Exponential backoff base for sync retries: `delay = sync_base_delay * sync_backoff.pow(n)`.
    pub(crate) sync_backoff: u32,
    /// Initial delay before the first retry; multiplied by the exponential backoff on each
    /// subsequent attempt.
    pub(crate) sync_base_delay: Duration,
}

impl OperatorWalletConfig {
    /// Creates a new config with the sync-retry knobs at their defaults
    /// ([`DEFAULT_SYNC_RETRIES`] / [`DEFAULT_SYNC_BACKOFF`] / [`DEFAULT_SYNC_BASE_DELAY`]).
    /// Use [`Self::with_sync_policy`] to override them.
    pub const fn new(cpfp_value: Amount, network: Network) -> Self {
        Self {
            cpfp_value,
            network,
            sync_retries: DEFAULT_SYNC_RETRIES,
            sync_backoff: DEFAULT_SYNC_BACKOFF,
            sync_base_delay: DEFAULT_SYNC_BASE_DELAY,
        }
    }

    /// Returns a copy with the sync-retry policy replaced. Useful for tests that want to
    /// disable backoff entirely (`sync_retries = 0`).
    pub const fn with_sync_policy(
        mut self,
        sync_retries: u32,
        sync_backoff: u32,
        sync_base_delay: Duration,
    ) -> Self {
        self.sync_retries = sync_retries;
        self.sync_backoff = sync_backoff;
        self.sync_base_delay = sync_base_delay;
        self
    }
}
