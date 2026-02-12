//! Configuration shared across all graph state machines.

use bitcoin::Network;

/// Bridge-wide configuration shared across all graph state machines.
///
/// These configurations are static over the lifetime of the bridge protocol
/// and apply uniformly to all graph state machine instances.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GraphSMCfg {
    /// The Bitcoin network (mainnet, testnet, regtest, etc.) used by the bridge.
    pub network: Network,

    /// The number of operators in the bridge.
    pub num_operators: usize,
}

impl GraphSMCfg {
    /// Returns the Bitcoin network used by the bridge.
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Returns the number of operators in the bridge.
    pub const fn num_operators(&self) -> usize {
        self.num_operators
    }
}
