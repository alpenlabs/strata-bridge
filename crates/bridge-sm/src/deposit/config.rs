//! Configuration shared across all deposit state machines.

use bitcoin::{Amount, Network};
use serde::{Deserialize, Serialize};
use strata_l1_txfmt::MagicBytes;

/// Configuration for a deposit state machine.
///
/// A snapshot of the protocol params in effect when the deposit was created. It is owned by that
/// deposit for its lifetime and persisted alongside it, so rolling `params.toml` changes the params
/// of subsequent deposits without disturbing the ones already in flight.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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

#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::bridge_fixtures::{
        TEST_DEPOSIT_AMOUNT, TEST_MAGIC_BYTES, TEST_OPERATOR_FEE, TEST_RECOVERY_DELAY,
    };

    use super::*;

    /// `Network` and `MagicBytes` serialize differently depending on `is_human_readable`, and this
    /// config is persisted with postcard (non-human-readable). An upstream bump that switched
    /// either to a string-only impl would otherwise only surface when a node failed to recover its
    /// state machines.
    #[test]
    fn postcard_roundtrip() {
        let cfg = DepositSMCfg {
            network: Network::Regtest,
            cooperative_payout_timeout_blocks: 144,
            deposit_amount: TEST_DEPOSIT_AMOUNT,
            operator_fee: TEST_OPERATOR_FEE,
            magic_bytes: TEST_MAGIC_BYTES.into(),
            recovery_delay: TEST_RECOVERY_DELAY,
        };

        let bytes = postcard::to_allocvec(&cfg).expect("config must serialize");
        let decoded: DepositSMCfg = postcard::from_bytes(&bytes).expect("config must deserialize");

        assert_eq!(cfg, decoded);
    }
}
