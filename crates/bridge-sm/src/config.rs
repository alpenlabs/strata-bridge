//! Bridge-wide configuration shared across all state machines.

use bitcoin::{Amount, Network};

/// Bridge-wide configuration shared across all state machines.
///
/// These configurations are static over the lifetime of the bridge protocol
/// and apply to all state machines (e.g., protocol parameters, network settings).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BridgeCfg {
    /// The Bitcoin network (mainnet, testnet, regtest, etc.) for the bridge.
    pub network: Network,
    /// The number of blocks after fulfillment confirmation after which the cooperative
    /// payout path is considered to have failed.
    pub cooperative_payout_timeout_blocks: u64,
    /// The deposit amount.
    pub deposit_amount: Amount,
}

impl BridgeCfg {
    /// Returns the Bitcoin network.
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Returns the cooperative payout timeout in blocks.
    pub const fn cooperative_payout_timeout_blocks(&self) -> u64 {
        self.cooperative_payout_timeout_blocks
    }

    /// Returns the deposit amount.
    pub const fn deposit_amount(&self) -> Amount {
        self.deposit_amount
    }
}
