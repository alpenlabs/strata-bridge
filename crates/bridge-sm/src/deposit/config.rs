//! Configuration for the Deposit State Machine.

use bitcoin::OutPoint;
use strata_bridge_primitives::{operator_table::OperatorTable, types::DepositIdx};

/// Per-instance configuration for a single Deposit State Machine.
///
/// These configurations are static over the lifetime of a single Deposit State Machine
/// and identify/configure a specific deposit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositSMCfg {
    /// The index of the deposit being tracked in a Deposit State Machine.
    pub deposit_idx: DepositIdx,
    /// The outpoint of the deposit being tracked in a Deposit State Machine.
    pub deposit_outpoint: OutPoint,
    /// The operators involved in the signing of this deposit.
    pub operator_table: OperatorTable,
}

impl DepositSMCfg {
    /// Returns the deposit index.
    pub const fn deposit_idx(&self) -> DepositIdx {
        self.deposit_idx
    }

    /// Returns the outpoint of the deposit transaction.
    pub const fn deposit_outpoint(&self) -> OutPoint {
        self.deposit_outpoint
    }

    /// Returns the operator table.
    pub const fn operator_table(&self) -> &OperatorTable {
        &self.operator_table
    }
}
