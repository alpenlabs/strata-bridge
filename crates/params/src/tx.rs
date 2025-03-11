//! Default values for transactions in the bridge.

use bitcoin::{relative, Amount};

/// The default min relay fee as defined in bitcoin-core with the unit sats/kvB.
///
/// This is set to a larger value (3 in bitcoin-core) to cross the dust threshold for certain
/// outputs. Setting this to a very high value may alleviate the need for an `anyone_can_pay`
/// output. In its current configuration of `10`, the total transaction fee for withdrawal
/// transaction computes to ~5.5 sats/vB (run integration tests with `RUST_LOG=warn` to verify).
pub const MIN_RELAY_FEE: Amount = Amount::from_sat(5000);

/// The default denomination for each deposit to the bridge.
pub const BRIDGE_DENOMINATION: Amount = Amount::from_int_btc(1);

/// The default amount of BTC that is staked by an operator.
pub const OPERATOR_STAKE: Amount = Amount::from_int_btc(3);

/// The default amount of BTC that is burnt when an operator's stake is slashed.
pub const BURN_AMOUNT: Amount = Amount::from_int_btc(1);

/// The default number of blocks between each stake transaction enforced via relative timelocks.
pub const STAKE_TX_DELTA: relative::LockTime = relative::LockTime::from_height(6);

/// The default number of ongoing past `Claim` transactions that can be used to slash an operator's
/// stake.
pub const NUM_SLASH_STAKE_TX: usize = 24;

/// The default fee charged by the operator to process a withdrawal.
///
/// This has the type [`Amount`] for convenience.
pub const OPERATOR_FEE: Amount = Amount::from_int_btc(2);

/// The default output amount in the challenge transaction that is paid to the operator that is
/// being challenged.
pub const CHALLENGE_COST: Amount = Amount::from_int_btc(1);

/// The default reward for a successful disprover.
pub const DISPROVER_REWARD: Amount = Amount::from_int_btc(1);

/// The default reward for a successful slashing.
pub const SLASH_STAKE_REWARD: Amount = Amount::from_sat(199_999_000); // 2 BTC - 1000 sats
