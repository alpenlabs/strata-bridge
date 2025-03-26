//! Default values for transactions in the bridge.

use bitcoin::{relative, Amount};

/// The default tag for the bridge.
pub(crate) const BRIDGE_TAG: &str = "alpen";

/// The default denomination for each deposit to the bridge.
pub(crate) const BRIDGE_DENOMINATION: Amount = Amount::from_int_btc(10);

/// The default amount of BTC that is staked by an operator.
pub(crate) const OPERATOR_STAKE: Amount = Amount::from_int_btc(3);

/// The default amount of BTC that is burnt when an operator's stake is slashed.
pub(crate) const BURN_AMOUNT: Amount = Amount::from_int_btc(1);

/// The default number of blocks between each stake transaction enforced via relative timelocks.
pub(crate) const STAKE_TX_DELTA: relative::LockTime = relative::LockTime::from_height(6);

/// The default number of ongoing past `Claim` transactions that can be used to slash an operator's
/// stake.
pub(crate) const NUM_SLASH_STAKE_TX: usize = 24;

/// The default fee charged by the operator to process a withdrawal.
///
/// This has the type [`Amount`] for convenience.
pub(crate) const OPERATOR_FEE: Amount = Amount::from_int_btc(2);

/// The default output amount in the challenge transaction that is paid to the operator that is
/// being challenged.
pub(crate) const CHALLENGE_COST: Amount = Amount::from_int_btc(1);

/// The default number of blocks for which the Deposit Request output must be locked before it can
/// be taken back by the user.
pub(crate) const REFUND_DELAY: u16 = 144 * 7; // 7 days' of worth of blocks in mainnet
