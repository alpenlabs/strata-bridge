//! Context for the Deposit State Machine.

use bitcoin::OutPoint;
use strata_bridge_primitives::{operator_table::OperatorTable, types::DepositIdx};

/// Execution context for a single instance of the Deposit State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositSMCtx {
    /// The index of the deposit being tracked in a Deposit State Machine.
    pub deposit_idx: DepositIdx,
    /// The output UTXO of the deposit request transaction being tracked in a Deposit State
    /// Machine.
    pub deposit_outpoint: OutPoint,
    /// The operators involved in the signing of this deposit.
    pub operator_table: OperatorTable,
}

impl DepositSMCtx {
    /// Returns the deposit index.
    pub const fn deposit_idx(&self) -> DepositIdx {
        self.deposit_idx
    }

    /// Returns the outpoint of the deposit request transaction.
    pub const fn deposit_outpoint(&self) -> OutPoint {
        self.deposit_outpoint
    }

    /// Returns the operator table.
    pub const fn operator_table(&self) -> &OperatorTable {
        &self.operator_table
    }
}
