//! Database types that are agnostic to the underlying database implementation.

/// Which transaction the stored outpoints fund.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[repr(u8)]
pub enum FundingPurpose {
    /// Operator-controlled UTXOs that fund the withdrawal fulfillment tx.
    WithdrawalFulfillment = 0,
    /// UTXO that funds the claim tx (typically a single outpoint).
    Claim = 1,
}

impl FundingPurpose {
    /// Converts from a `u8` discriminant.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::WithdrawalFulfillment),
            1 => Some(Self::Claim),
            _ => None,
        }
    }
}
