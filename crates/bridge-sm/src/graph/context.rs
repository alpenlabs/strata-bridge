//! Context for the Graph State Machine.

use bitcoin::{OutPoint, XOnlyPublicKey, hashes::sha256};
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    types::{DepositIdx, GraphIdx, OperatorIdx},
};
use strata_bridge_tx_graph::game_graph::{KeyData, SetupParams};

use crate::graph::config::GraphSMCfg;

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
    pub fn generate_setup_params(&self, cfg: &GraphSMCfg) -> SetupParams {
        let keys = self.generate_key_data(cfg);

        SetupParams {
            operator_index: self.graph_idx.operator,
            stake_outpoint: self.stake_outpoint,
            keys,
        }
    }

    /// Generates the [`KeyData`] required for graph generation using static configuration
    /// parameters.
    pub fn generate_key_data(&self, cfg: &GraphSMCfg) -> KeyData {
        let n_of_n_pubkey = self
            .operator_table()
            .aggregated_btc_key()
            .x_only_public_key()
            .0;

        let owner_idx = self.operator_idx() as usize;
        let adaptor_key = cfg.operator_adaptor_keys[owner_idx];
        let watchtower_pubkeys = self.watchtower_pubkeys();

        let admin_pubkey = cfg.admin_pubkey;
        let unstaking_image = self.unstaking_image();
        let wt_fault_pubkeys = self.watchtower_fault_pubkeys(&cfg.watchtower_fault_pubkeys);

        let owner_desc = cfg.payout_descs[owner_idx].clone();
        let slash_watchtower_descriptors = cfg
            .payout_descs
            .iter()
            .filter(|desc| *desc != &owner_desc)
            .cloned()
            .collect();

        KeyData {
            n_of_n_pubkey,
            operator_pubkey: adaptor_key,
            watchtower_pubkeys,
            admin_pubkey,
            unstaking_image,
            wt_fault_pubkeys,
            operator_descriptor: owner_desc,
            slash_watchtower_descriptors,
        }
    }

    /// Returns the list of watchtower pubkeys for this graph.
    pub fn watchtower_pubkeys(&self) -> Vec<XOnlyPublicKey> {
        let owner_idx = self.operator_idx();
        let owner_pubkey = self
            .operator_table()
            .idx_to_btc_key(&owner_idx)
            .expect("operator index must be valid")
            .x_only_public_key()
            .0;

        // NOTE: (@Rajil1213) derive watchtower pubkeys directly from the operator table until we
        // support standalone modes for operators and watchtowers. Optionally, couple them further
        // by moving this logic _inside_ the operator table.
        self.operator_table()
            .btc_keys()
            .into_iter()
            .filter(|key| key.x_only_public_key().0 != owner_pubkey)
            .map(|key| key.x_only_public_key().0)
            .collect()
    }

    /// Returns the list of watchtower fault pubkeys for this graph.
    pub fn watchtower_fault_pubkeys(
        &self,
        all_fault_pubkeys: &[XOnlyPublicKey],
    ) -> Vec<XOnlyPublicKey> {
        let expected_watchtower_count = self.watchtower_pubkeys().len();

        // Support both config shapes:
        // - already watchtower-only fault keys (len == n-1)
        // - per-operator fault keys (len == n), where owner's entry must be skipped
        if all_fault_pubkeys.len() == expected_watchtower_count {
            return all_fault_pubkeys.to_vec();
        }

        let owner_idx = self.operator_idx() as usize;

        all_fault_pubkeys
            .iter()
            .enumerate()
            .filter(|(idx, _)| *idx != owner_idx)
            .map(|(_, pubkey)| *pubkey)
            .collect()
    }
}
