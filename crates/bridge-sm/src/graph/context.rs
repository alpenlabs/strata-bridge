//! Context for the Graph State Machine.

use bitcoin::{OutPoint, hashes::sha256};
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    types::{DepositIdx, GraphIdx, OperatorIdx},
};
use strata_bridge_tx_graph2::game_graph::{KeyData, SetupParams};

/// Execution context for a single instance of the Graph State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GraphSMCtx {
    /// The index of the graph represented by the deposit and the operator this graph is associated
    /// with.
    pub graph_idx: GraphIdx,

    /// The deposit UTXO this graph is associated with.
    pub deposit_outpoint: OutPoint,

    /// The stake UTXO that will be spent by the watchtowers if an operator is faulty.
    pub stake_outpoint: OutPoint,

    /// The hash (image) that locks the claim-payout connector.
    ///
    /// Its preimage is revealed when an operator initiates an unstaking process.
    pub unstaking_image: sha256::Hash,

    /// The operator table for the graph state machine instance.
    pub operator_table: OperatorTable,
}

impl GraphSMCtx {
    /// Returns the index of the deposit this graph is associated with.
    pub const fn deposit_idx(&self) -> DepositIdx {
        self.graph_idx.deposit
    }

    /// Returns the index of the operator this graph belongs to.
    pub const fn operator_idx(&self) -> OperatorIdx {
        self.graph_idx.operator
    }

    /// Returns the GraphID for this graph.
    pub const fn graph_idx(&self) -> GraphIdx {
        self.graph_idx
    }

    /// Returns the deposit UTXO this graph is associated with.
    pub const fn deposit_outpoint(&self) -> OutPoint {
        self.deposit_outpoint
    }

    /// Returns the stake UTXO that will be spent by the watchtowers if an operator is faulty.
    pub const fn stake_outpoint(&self) -> OutPoint {
        self.stake_outpoint
    }

    /// Returns the hash (image) that locks the claim-payout connector.
    ///
    /// Its preimage is revealed when an operator initiates an unstaking process.
    pub const fn unstaking_image(&self) -> sha256::Hash {
        self.unstaking_image
    }

    /// Returns the operator table for the graph state machine instance.
    pub const fn operator_table(&self) -> &OperatorTable {
        &self.operator_table
    }

    /// Generates the [`SetupParams`] required for graph generation.
    pub const fn generate_setup_params(&self, key_data: KeyData) -> SetupParams {
        SetupParams {
            operator_index: self.graph_idx.operator,
            stake_outpoint: self.stake_outpoint,
            keys: key_data,
        }
    }
}
