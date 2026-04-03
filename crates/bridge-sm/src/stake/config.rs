//! Configuration shared across all Stake State Machines instances.

use serde::{Deserialize, Serialize};
use strata_bridge_tx_graph::stake_graph::ProtocolParams;

/// Bridge-wide configuration shared across all Stake State Machine instances.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StakeSMCfg {
    /// The static configurations of the unstaking graph that are inherent to the protocol.
    pub protocol_params: ProtocolParams,
}
