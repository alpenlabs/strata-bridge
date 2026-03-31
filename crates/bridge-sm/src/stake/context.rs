//! Context for the Stake State Machine.

use bitcoin::{OutPoint, hashes::sha256};
use bitcoin_bosd::Descriptor;
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{operator_table::OperatorTable, types::OperatorIdx};
use strata_bridge_tx_graph::stake_graph::SetupParams;

/// Execution context for a single instance of a Stake State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct StakeSMCtx {
    // Invariant: `operator_idx` is included in `operator_table`.
    /// The index of the operator whose stake is tracked by this state machine.
    operator_idx: OperatorIdx,

    /// The operator table for this state machine instance.
    operator_table: OperatorTable,
}

impl StakeSMCtx {
    /// Creates a new Stake State Machine context.
    ///
    /// # Panics
    ///
    /// This method panics if the operator index is not included in the operator table.
    pub fn new(operator_idx: OperatorIdx, operator_table: OperatorTable) -> Self {
        assert!(
            operator_table.contains_idx(&operator_idx),
            "The operator index must be included in the operator table"
        );

        Self {
            operator_idx,
            operator_table,
        }
    }

    /// Returns the index of the operator whose stake is tracked.
    pub const fn operator_idx(&self) -> OperatorIdx {
        self.operator_idx
    }

    /// Returns the operator table.
    pub const fn operator_table(&self) -> &OperatorTable {
        &self.operator_table
    }

    /// Constructs the complete set of information required to construct the unstaking graph.
    ///
    /// # Parameters
    ///
    /// - `stake_funds`: The funding input for the stake transaction.
    /// - `unstaking_image`: The unstaking hash image whose preimage is revealed in the `Unstaking
    /// Intent` transaction
    /// - `unstaking_output_desc`: The descriptor where the operator wants to receive the staked
    ///   funds after unstaking.
    pub fn generate_setup_params(
        &self,
        stake_funds: OutPoint,
        unstaking_image: sha256::Hash,
        unstaking_output_desc: Descriptor,
    ) -> SetupParams {
        SetupParams {
            operator_index: self.operator_idx(),
            n_of_n_pubkey: self
                .operator_table()
                .aggregated_btc_key()
                .x_only_public_key()
                .0,
            unstaking_image,
            unstaking_operator_descriptor: unstaking_output_desc,
            stake_funds,
        }
    }
}
