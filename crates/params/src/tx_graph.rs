//! This module contains parameters required to construct the peg-out graph.

use bitcoin::Amount;
use serde::{Deserialize, Serialize};

use super::tx::BRIDGE_DENOMINATION;
use crate::tx::{CHALLENGE_COST, OPERATOR_FEE};

/// The parameters required to construct a peg-out graph.
///
/// These parameters are consensus-critical meaning that these are values that are agreed upon by
/// all operators and verifiers in the bridge.
// TODO: move this to the primitives crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PegOutGraphParams {
    /// The amount that is locked in the bridge address at the deposit time.
    pub deposit_amount: Amount,

    /// The fee charged by an operator for processing a withdrawal.
    pub operator_fee: Amount,

    /// The output amount for the challenge transaction that is paid to the operator being
    /// challenged.
    pub challenge_cost: Amount,
}

impl Default for PegOutGraphParams {
    fn default() -> Self {
        Self {
            deposit_amount: BRIDGE_DENOMINATION,
            operator_fee: OPERATOR_FEE,
            challenge_cost: CHALLENGE_COST,
        }
    }
}
