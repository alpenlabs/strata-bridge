//! Configuration for the Deposit State Machine.

// TODO: (@Rajil1213) Maybe move configuration to a separate `config` module.
// This module will have a
// - `DepositSMCfg` which contains values that are static over the
//  lifetime of a single Deposit State Machine, and a
// - `DepositGlobalCfg` which contains values that are static over the lifetime of all Deposit State
//   Machines
//  (such as timelocks).
use bitcoin::{Amount, Network, OutPoint};
use strata_bridge_primitives::{operator_table::OperatorTable, types::DepositIdx};

/// The static configuration for a Deposit State Machine.
///
/// These configurations are set at the creation of the Deposit State Machine and do not change
/// during any state transition.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositCfg {
    /// The index of the deposit being tracked in a Deposit State Machine.
    pub(super) deposit_idx: DepositIdx,
    /// The outpoint of the deposit being tracked in a Deposit State Machine.
    pub(super) deposit_outpoint: OutPoint,
    /// The operators involved in the signing of this deposit.
    pub(super) operator_table: OperatorTable,
    /// The network (mainnet, testnet, regtest, etc.) for the deposit.
    // FIXME: (@mukeshdroid) network should not be part of state but a static config.
    pub(super) network: Network,
    /// The deposit amount.
    // FIXME: (@mukeshdroid) deposit amount should not be part of state but a static config.
    pub(super) deposit_amount: Amount,
}

impl DepositCfg {
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
