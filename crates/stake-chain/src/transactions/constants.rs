//! Constants used in the stake chain.

use bitcoin::Amount;

/// The [`Amount`] needed to cover for dust outputs in each `k`th
/// [`StakeTx`](crate::transactions::StakeTx).
///
/// The dust limit for SegWit transactions is `330` sats.
///
/// For each single [`StakeTx`](crate::transactions::StakeTx), the number of dust outputs is:
///
/// - 71 pairs of dust outputs for the "Assert-data" transaction: `330 * 2 * 71 = 46_860` sats.
/// - 1 pair of dust outputs for the "Claim" transaction: `330 * 2 = 660` sats.
/// - 1 dust output for the "Burn Payouts" transaction: `330` sats.
/// - 1 dust output for the CPFP in the "Pre-Assert" transaction: `330` sats.
/// - 1 dust output for the CPFP for the "Claim" transaction: `330` sats.
/// - 1 dust output for the CPFP for the "Stake" transaction itself: `330` sats.
///
/// The total is: `46_860 + 660 + 330 + 330 = 53_460` sats.
pub const OPERATOR_FUNDS: Amount =
    Amount::from_sat((330 * 2 * 71) + (330 * 2) + 330 + 330 + 330 + 330);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operator_funds() {
        assert_eq!(OPERATOR_FUNDS, Amount::from_sat(48_840));
    }
}
