//! Configuration shared across all deposit state machines.

use bitcoin::{Amount, Network};
use strata_l1_txfmt::MagicBytes;

/// Bridge-wide configuration shared across all deposit state machines.
///
/// These configurations are static over the lifetime of the bridge protocol
/// and apply uniformly to all deposit state machine instances.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositSMCfg {
    /// The Bitcoin network (mainnet, testnet, regtest, etc.) used by the bridge.
    pub network: Network,
    /// The number of blocks after fulfillment confirmation after which the
    /// cooperative payout path is considered to have failed.
    pub cooperative_payout_timeout_blocks: u64,
    /// The fixed deposit amount expected by the bridge protocol.
    pub deposit_amount: Amount,
    /// The fee amount that the operator charges for fronting a user.
    pub operator_fee: Amount,
    /// The "magic bytes" used in the OP_RETURN of the transactions to identify it as relevant to
    /// the bridge.
    pub magic_bytes: MagicBytes,
    /// The number of blocks after which the user can take back their deposit request.
    pub recovery_delay: u16,
}

impl DepositSMCfg {
    /// Returns the Bitcoin network used by the bridge.
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Returns the cooperative payout timeout, in blocks.
    pub const fn cooperative_payout_timeout_blocks(&self) -> u64 {
        self.cooperative_payout_timeout_blocks
    }

    /// Returns the expected deposit amount.
    pub const fn deposit_amount(&self) -> Amount {
        self.deposit_amount
    }

    /// Returns the operator fee amount.
    pub const fn operator_fee(&self) -> Amount {
        self.operator_fee
    }

    /// Returns the magic bytes used in the OP_RETURN of relevant transactions.
    pub const fn magic_bytes(&self) -> MagicBytes {
        self.magic_bytes
    }
}
