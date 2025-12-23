//! Static configuration common to all duty executors.

use bitcoin::Network;

/// The static configuration for the duty executors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExecutionConfig {
    /// The Bitcoin network to operate on.
    pub network: Network,

    /// The minimum number of blocks required between the current block height and the withdrawwal
    /// fulfillment deadline in order to perform a fulfillment.
    pub min_withdrawal_fulfillment_window: u64,
}
