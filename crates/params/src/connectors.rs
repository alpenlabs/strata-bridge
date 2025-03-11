//! Params related to the bridge tx graph connectors, specifically the layout of assert-data
//! connectors.

use serde::{Deserialize, Serialize};

/// The consensus-critical parameters that define the locking conditions for each connector.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ConnectorParams {
    /// The relative timelock (measured in number of blocks) on the [`ClaimTx`] output that is used
    /// to lock funds in the N-of-N and used in the [`PayoutOptimisticTx`].
    pub payout_optimistic_timelock: u32,

    /// The relative timelock (measured in number of blocks) on the [`ClaimTx`] output that is used
    /// to lock funds in the N-of-N and used in the [`PreAssertTx`].
    pub pre_assert_timelock: u32,

    /// The relative timelock (measure in number of blocks) on the [`PostAssertTx`] output that is
    /// used to lock funds in the N-of-N and used in the [`PayoutTx`].
    pub payout_timelock: u32,
}

impl Default for ConnectorParams {
    fn default() -> Self {
        Self {
            payout_optimistic_timelock: 1008, // 1 week's worth of blocks in Mainnet
            pre_assert_timelock: 1152,        // 1 week + 1 day's worth of blocks in Mainnet
            payout_timelock: 1008,            // 1 week's worth of block in Mainnet.
        }
    }
}
