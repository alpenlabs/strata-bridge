//! This module contains parameters required to construct the peg-out graph.

use bitcoin::Amount;
use serde::{Deserialize, Serialize};

use super::default::{BRIDGE_DENOMINATION, CHALLENGE_COST, OPERATOR_FEE, REFUND_DELAY, TAG_SIZE};
use crate::default::BRIDGE_TAG;

/// The parameters required to construct a peg-out graph.
///
/// These parameters are consensus-critical meaning that these are values that are agreed upon by
/// all operators and verifiers in the bridge.
// TODO: move this to the primitives crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PegOutGraphParams {
    /// The tag, also known as "magic bytes".
    pub tag: String,

    /// The amount that is locked in the bridge address at the deposit time.
    pub deposit_amount: Amount,

    /// The fee charged by an operator for processing a withdrawal.
    pub operator_fee: Amount,

    /// The output amount for the challenge transaction that is paid to the operator being
    /// challenged.
    pub challenge_cost: Amount,

    /// The number of blocks for which the Deposit Request output must be locked before it can be
    /// taken back by the user.
    pub refund_delay: u16,
}

impl PegOutGraphParams {
    /// Validates the parameters to ensure they meet the requirements.
    ///
    /// This function validates:
    ///
    /// - Tag must be exactly 4 bytes
    ///
    /// Returns an error if any validation fails.
    pub fn validate(&self) -> Result<(), String> {
        if self.tag.as_bytes().len() != TAG_SIZE {
            return Err(format!(
                "Tag size must be exactly {} bytes, got {} bytes",
                TAG_SIZE,
                self.tag.as_bytes().len()
            ));
        }
        Ok(())
    }
}

impl Default for PegOutGraphParams {
    fn default() -> Self {
        Self {
            tag: BRIDGE_TAG.to_string(),
            deposit_amount: BRIDGE_DENOMINATION,
            operator_fee: OPERATOR_FEE,
            challenge_cost: CHALLENGE_COST,
            refund_delay: REFUND_DELAY,
        }
    }
}
