//! Static configuration common to all duty executors.

use bitcoin::Network;

/// The static configuration for the duty executors.
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    /// The Bitcoin network to operate on.
    pub network: Network,

    /// The number of blocks before the withdrawal fulfillment deadline after which the operator
    /// will not attempt to perform a fulfillment. This is a safety mechanism.
    pub min_withdrawal_fulfillment_window: u64,
}
