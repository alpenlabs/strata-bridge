//! Provides types/traits associated with the withdrawal process.

use bitcoin::OutPoint;
use bitcoin_bosd::Descriptor;
use serde::{Deserialize, Serialize};

use crate::types::{BitcoinBlockHeight, OperatorIdx};

/// Details for a withdrawal info assigned to an operator.
///
/// It has all the information required to create a transaction for fulfilling a user's withdrawal
/// request and pay operator fees.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WithdrawalInfo {
    /// The [`OutPoint`] of the UTXO in the Bridge Address that is to be used to service the
    /// withdrawal request.
    deposit_outpoint: OutPoint,

    /// The x-only public key of the user used to create the taproot address that the user can
    /// spend from.
    user_destination: Descriptor,

    /// The index of the operator that is assigned the withdrawal.
    assigned_operator_idx: OperatorIdx,

    /// The bitcoin block height before which the withdrawal has to be processed.
    ///
    /// Any withdrawal request whose `exec_deadline` is before the current bitcoin block height is
    /// considered stale and must be ignored.
    exec_deadline: BitcoinBlockHeight,
}

// fn deserialize_hex_xonly_pubkey<'de, D>(deserializer: D) -> Result<XOnlyPublicKey, D::Error>
// where
//     D: Deserializer<'de>,
// {
//     let hex_str: String = Deserialize::deserialize(deserializer)?;

//     // Strip the `0x` prefix if it exists
//     let hex_str = hex_str.strip_prefix("0x").unwrap_or(&hex_str);

//     // Parse the hex string to XOnlyPublicKey
//     XOnlyPublicKey::from_str(hex_str).map_err(de::Error::custom)
// }

impl WithdrawalInfo {
    /// Create a new withdrawal request.
    pub fn new(
        deposit_outpoint: OutPoint,
        user_destination: Descriptor,
        assigned_operator_idx: OperatorIdx,
        exec_deadline: BitcoinBlockHeight,
    ) -> Self {
        Self {
            deposit_outpoint,
            user_destination,
            assigned_operator_idx,
            exec_deadline,
        }
    }

    /// Get the outpoint of the deposit UTXO that this withdrawal spends.
    pub fn deposit_outpoint(&self) -> OutPoint {
        self.deposit_outpoint
    }

    /// Get the assignee for this withdrawal request.
    pub fn assigned_operator_idx(&self) -> OperatorIdx {
        self.assigned_operator_idx
    }

    /// Get the recipient's [`Descriptor`].
    pub fn user_destination(&self) -> &Descriptor {
        &self.user_destination
    }

    /// Get the execution deadline for the request.
    pub fn exec_deadline(&self) -> u64 {
        self.exec_deadline
    }

    /// Check if the passed bitcoin block height is greater than the deadline for the withdrawal.
    pub fn is_expired_at(&self, block_height: BitcoinBlockHeight) -> bool {
        self.exec_deadline < block_height
    }
}
