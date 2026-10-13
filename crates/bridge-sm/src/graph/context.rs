//! Context for the Graph State Machine.

use bitcoin::{OutPoint, XOnlyPublicKey, hashes::sha256};
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{
    covenant::{CovenantId, StakeKey},
    operator_table::OperatorTable,
    types::{DepositIdx, GraphIdx, OperatorIdx},
};
use strata_bridge_tx_graph::game_graph::{DepositParams, KeyData, SetupParams};

use crate::graph::config::GraphSMCfg;

/// Execution context for a single instance of the Graph State Machine.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GraphSMCtx {
    /// The covenant whose stake and membership this graph permanently uses.
    pub covenant: CovenantId,

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
    /// Returns the exact stake instance bound to this graph.
    pub const fn stake_key(&self) -> StakeKey {
        StakeKey {
            covenant: self.covenant,
            operator: self.graph_idx.operator,
        }
    }

    /// Returns the index of the deposit this graph is associated with.
    pub const fn deposit_idx(&self) -> DepositIdx {
        self.graph_idx.deposit
    }

    /// Returns the index of the operator this graph belongs to.
    pub const fn operator_idx(&self) -> OperatorIdx {
        self.graph_idx.operator
    }

    /// Returns the graph owner's BIP-340 x-only key.
    pub fn owner_btc_x_only_key(&self) -> XOnlyPublicKey {
        self.operator_table
            .idx_to_btc_x_only_key(&self.operator_idx())
            .expect("graph owner must be present in its own operator table snapshot")
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
    ///
    /// The adaptor and fault pubkeys are drawn from the deposit-time parameters, since they
    /// are only known once the graph owner has fetched them from mosaic at deposit time.
    pub fn generate_setup_params(
        &self,
        cfg: &GraphSMCfg,
        deposit_params: &DepositParams,
    ) -> SetupParams {
        let keys = self.generate_key_data(cfg, deposit_params);

        SetupParams {
            operator_index: self.graph_idx.operator,
            stake_outpoint: self.stake_outpoint,
            keys,
        }
    }

    /// Generates the [`KeyData`] required for graph generation.
    ///
    /// Static keys come from `cfg`; the owner's adaptor pubkey and the per-watchtower fault
    /// pubkeys come from `deposit_params` because they are produced per-deposit by mosaic.
    pub fn generate_key_data(&self, cfg: &GraphSMCfg, deposit_params: &DepositParams) -> KeyData {
        let n_of_n_pubkey = self
            .operator_table()
            .aggregated_btc_key()
            .x_only_public_key()
            .0;

        let owner_idx = self.operator_idx();
        let watchtower_pubkeys = self.watchtower_pubkeys();

        let admin = cfg.admin.clone();
        let unstaking_image = self.unstaking_image();

        let payout_desc = |idx: &OperatorIdx| {
            cfg.payout_descs.get(idx).cloned().unwrap_or_else(|| {
                panic!("startup reconciliation registers a payout descriptor for operator {idx}")
            })
        };
        let owner_desc = payout_desc(&owner_idx);
        let slash_watchtower_descriptors = self
            .operator_table()
            .operator_idxs()
            .iter()
            .filter(|idx| **idx != owner_idx)
            .map(payout_desc)
            .collect();

        let operator_pubkey = self
            .operator_table()
            .idx_to_btc_key(&self.operator_idx())
            .expect("operator index must be valid")
            .x_only_public_key()
            .0;

        KeyData {
            n_of_n_pubkey,
            operator_pubkey,
            operator_adaptor_pubkeys: deposit_params.adaptor_pubkeys.clone(),
            watchtower_pubkeys,
            admin,
            unstaking_image,
            wt_fault_pubkeys: deposit_params.fault_pubkeys.clone(),
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
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use bitcoin_bosd::Descriptor;
    use strata_bridge_primitives::operator_table::PublicOperatorTable;
    use strata_bridge_test_utils::bridge_fixtures::{random_p2tr_desc, test_operator_table};

    use super::*;
    use crate::graph::{
        machine::generate_game_graph,
        tests::{test_deposit_params, test_graph_sm_cfg, test_graph_sm_ctx},
    };

    const REGISTERED: u32 = 4;

    /// A graph owned by `owner` whose covenant contains only `members` out of [`REGISTERED`]
    /// registrations.
    fn graph_ctx(members: &[OperatorIdx], owner: OperatorIdx) -> GraphSMCtx {
        let registered = test_operator_table(REGISTERED as usize, 0);
        let entries = members
            .iter()
            .map(|idx| {
                (
                    *idx,
                    registered.idx_to_p2p_key(idx).expect("registered").clone(),
                    registered.idx_to_btc_key(idx).expect("registered"),
                )
            })
            .collect();
        let mut ctx = test_graph_sm_ctx();
        ctx.operator_table = PublicOperatorTable::from_entries(entries)
            .expect("valid membership")
            .with_pov(owner)
            .expect("owner is a member");
        ctx.graph_idx.operator = owner;
        ctx
    }

    fn cfg_with(payout_descs: BTreeMap<OperatorIdx, Descriptor>) -> GraphSMCfg {
        GraphSMCfg {
            payout_descs,
            ..(*test_graph_sm_cfg()).clone()
        }
    }

    fn registered_descs() -> BTreeMap<OperatorIdx, Descriptor> {
        (0..REGISTERED)
            .map(|idx| (idx, random_p2tr_desc()))
            .collect()
    }

    #[test]
    fn slash_descriptors_cover_only_the_graph_watchtowers() {
        let descs = registered_descs();
        let cfg = cfg_with(descs.clone());
        let ctx = graph_ctx(&[0, 2, 3], 0);

        let keys = ctx.generate_key_data(&cfg, &test_deposit_params());

        assert_eq!(
            keys.operator_descriptor, descs[&0],
            "the owner is paid at its own descriptor"
        );
        assert_eq!(
            keys.slash_watchtower_descriptors,
            vec![descs[&2].clone(), descs[&3].clone()],
            "only the graph's watchtowers, in slot order, receive slash outputs"
        );
    }

    #[test]
    fn owner_descriptor_is_selected_by_operator_index() {
        let descs = registered_descs();
        let cfg = cfg_with(descs.clone());
        let ctx = graph_ctx(&[0, 2, 3], 3);

        let keys = ctx.generate_key_data(&cfg, &test_deposit_params());

        assert_eq!(
            keys.operator_descriptor, descs[&3],
            "operator 3 is the third member, but its descriptor is found by index"
        );
        assert_eq!(
            keys.slash_watchtower_descriptors,
            vec![descs[&0].clone(), descs[&2].clone()],
            "watchtowers exclude the owner and the non-member"
        );
    }

    #[test]
    fn shared_descriptors_keep_one_slash_output_per_watchtower() {
        let shared = random_p2tr_desc();
        let descs = BTreeMap::from([(0, shared.clone()), (1, shared), (2, random_p2tr_desc())]);
        let cfg = cfg_with(descs);
        let ctx = graph_ctx(&[0, 1, 2], 0);

        let keys = ctx.generate_key_data(&cfg, &test_deposit_params());

        assert_eq!(
            keys.slash_watchtower_descriptors.len(),
            ctx.watchtower_pubkeys().len(),
            "a watchtower sharing the owner's descriptor still gets a slash output"
        );
    }

    #[test]
    fn new_registrations_leave_existing_graphs_unchanged() {
        let ctx = test_graph_sm_ctx();
        let cfg = (*test_graph_sm_cfg()).clone();
        let deposit_params = test_deposit_params();
        let before = generate_game_graph(&cfg, &ctx, &deposit_params).summarize();

        let mut descs = cfg.payout_descs.clone();
        let next_idx = descs.keys().max().expect("registered operators") + 1;
        descs.insert(next_idx, random_p2tr_desc());
        let extended = GraphSMCfg {
            payout_descs: descs,
            ..cfg
        };
        let after = generate_game_graph(&extended, &ctx, &deposit_params).summarize();

        assert_eq!(
            before, after,
            "registering another operator must not change an existing graph's transactions"
        );
    }

    #[test]
    fn slash_descriptors_follow_watchtower_order() {
        let descs = registered_descs();
        let cfg = cfg_with(descs.clone());
        let ctx = graph_ctx(&[0, 1, 3], 1);
        let members = ctx.operator_table().operator_idxs();

        let keys = ctx.generate_key_data(&cfg, &test_deposit_params());

        let watchtowers: BTreeSet<_> = members.into_iter().filter(|idx| *idx != 1).collect();
        assert_eq!(
            keys.slash_watchtower_descriptors,
            watchtowers
                .iter()
                .map(|idx| descs[idx].clone())
                .collect::<Vec<_>>(),
            "slash output i must pay the watchtower in slot i"
        );
    }
}
