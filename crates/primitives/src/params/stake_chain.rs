//! Parameters for the Stake Chain protocol such as the staking amount, `n_of_n_agg_pubkey`, network
//! and `delta`.

use bitcoin::{relative, Amount};

use super::tx::{BURN_AMOUNT, NUM_SLASH_STAKE_TX, OPERATOR_STAKE, STAKE_TX_DELTA};

/// The Stake Chain public parameters that are inherent from the protocol and does not need to be
/// interactively shared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StakeChainParams {
    /// The Staking [`Amount`].
    // TODO: make this configurable with a fallback const `D_BTC`.
    pub stake_amount: Amount,

    /// The portion of the stake that is burnt during disprove.
    pub burn_amount: Amount,

    /// The delta value used for the stake chain.
    // TODO: make this configurable with a fallback const like FINALITY_DEPTH to something like
    //       `6`.
    pub delta: relative::LockTime,

    /// The number of past ongoing claims that can be used to slash a stake.
    pub slash_stake_count: usize,
}

impl Default for StakeChainParams {
    fn default() -> Self {
        Self {
            stake_amount: OPERATOR_STAKE,
            burn_amount: BURN_AMOUNT,
            delta: STAKE_TX_DELTA,
            slash_stake_count: NUM_SLASH_STAKE_TX,
        }
    }
}
