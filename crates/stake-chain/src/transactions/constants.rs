//! Constants used in the stake chain.

use bitcoin::Amount;

/// The [`Amount`] needed to cover for dust outputs in each `k`th
/// [`StakeTx`](crate::transactions::StakeTx).
///
/// The dust limit for SegWit transactions is `330` sats.
///
/// For each single [`StakeTx`](crate::transactions::StakeTx), the number of dust outputs is:
///
/// - 47 pairs of dust outputs for the "Assert-data" transactions: `330 * 2 * 47 = 31_020` sats.
/// - 1 pair of dust outputs for the "Claim" transaction: `330 * 2 = 660` sats.
/// - 1 dust output for the "Burn Payouts" transaction: `330` sats.
/// - 1 dust output for the CPFP in the "Pre-Assert" transaction: `330` sats.
/// - 1 dust output for the CPFP for the "Claim" transaction: `330` sats.
/// - 1 dust output for the CPFP for the "Stake" transaction itself: `330` sats.
///
/// The total is:
///
/// ```
/// # use bitcoin::Amount;
/// # use strata_bridge_stake_chain::transactions::constants::OPERATOR_FUNDS;
/// assert_eq!(OPERATOR_FUNDS, Amount::from_sat(33_000));
/// ```
pub const OPERATOR_FUNDS: Amount =
    Amount::from_sat((330 * 2 * 47) + (330 * 2) + 330 + 330 + 330 + 330);

/// SegWit minimal non-dust value.
pub const DUST_AMOUNT: Amount = Amount::from_sat(330);

/// [`StakeTx`](crate::transactions::StakeTx) stake output, i.e. the stake vout.
///
/// This is the third output.
pub const STAKE_VOUT: u32 = 2;
