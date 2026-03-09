//! Configuration shared across all Stake State Machines instances.

use bitcoin::relative::Height;

/// Default timelock for the unstaking transaction.
pub const DEFAULT_UNSTAKING_TIMELOCK: Height = Height::from_height(3_024);

/// Bridge-wide configuration shared across all Stake State Machine instances.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StakeSMCfg {
    /// Timelock for the unstaking transaction.
    pub unstaking_timelock: Height,
}

impl Default for StakeSMCfg {
    fn default() -> Self {
        Self {
            unstaking_timelock: DEFAULT_UNSTAKING_TIMELOCK,
        }
    }
}
