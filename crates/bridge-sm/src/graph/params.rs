//! The params owned by a single Graph State Machine instance.

use std::sync::Arc;

use bitcoin::Amount;
use strata_bridge_tx_graph::game_graph::{ClaimKeys, claim_funds_required};

use crate::graph::{config::GraphSMCfg, context::GraphSMCtx};

/// The params a single [`GraphSM`](crate::graph::machine::GraphSM) was created under, plus the
/// values derived from them.
///
/// These are snapshotted when the graph is created and persisted alongside it, so rolling
/// `params.toml` changes what subsequent graphs are built against without disturbing the ones
/// already in flight. Duty execution receives this rather than reading a process-global config,
/// which is what keeps the transactions an executor broadcasts in agreement with the state machine
/// that asked for them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GraphParams {
    cfg: Arc<GraphSMCfg>,
    claim_funding_value: Amount,
}

impl GraphParams {
    /// Snapshots `cfg` for the graph described by `ctx`.
    pub fn new(cfg: Arc<GraphSMCfg>, ctx: &GraphSMCtx) -> Self {
        let watchtower_pubkeys = ctx.watchtower_pubkeys();
        let claim_funding_value = claim_funds_required(
            &cfg.game_graph_params,
            ClaimKeys {
                n_of_n_pubkey: ctx
                    .operator_table()
                    .aggregated_btc_key()
                    .x_only_public_key()
                    .0,
                watchtower_pubkeys: &watchtower_pubkeys,
                admin: &cfg.admin,
                unstaking_image: ctx.unstaking_image(),
            },
        );

        Self {
            cfg,
            claim_funding_value,
        }
    }

    /// Returns the configuration this graph was created under.
    pub const fn cfg(&self) -> &Arc<GraphSMCfg> {
        &self.cfg
    }

    /// Returns the exact value of the reserved-wallet UTXO that funds this graph's claim
    /// transaction.
    ///
    /// The wallet selects claim-funding UTXOs by exact value, so graphs created under different
    /// params draw from separate pools.
    pub const fn claim_funding_value(&self) -> Amount {
        self.claim_funding_value
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::relative;
    use strata_bridge_test_utils::bridge_fixtures::{TEST_POV_IDX, test_operator_table};

    use super::*;
    use crate::graph::tests::{
        N_TEST_OPERATORS, test_deposit_params, test_graph_sm_cfg, test_graph_sm_ctx,
    };

    /// The wallet reserves a claim-funding UTXO by exact value and the claim transaction spends
    /// it, so the value derived here must equal the one `GameGraph::new` derives from the full
    /// `KeyData`. If they disagree the reservation finds nothing, the refill mints the wrong
    /// denomination, and duty execution panics on the post-refill `expect`.
    #[test]
    fn claim_funding_value_matches_game_graph() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();

        let key_data = ctx.generate_key_data(&cfg, &test_deposit_params());
        let from_game_graph =
            claim_funds_required(&cfg.game_graph_params, ClaimKeys::from(&key_data));

        assert_eq!(
            GraphParams::new(cfg, &ctx).claim_funding_value(),
            from_game_graph,
        );
    }

    /// The value depends on the watchtower count, which comes from this graph's own operator
    /// table rather than the full covenant set. A graph built for a reduced active set needs a
    /// different denomination than one built for the full set.
    #[test]
    fn claim_funding_value_varies_with_operator_count() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();

        let mut smaller_ctx = ctx.clone();
        smaller_ctx.operator_table = test_operator_table(N_TEST_OPERATORS - 1, TEST_POV_IDX);

        assert_ne!(
            GraphParams::new(cfg.clone(), &ctx).claim_funding_value(),
            GraphParams::new(cfg, &smaller_ctx).claim_funding_value(),
        );
    }

    /// Rolling `counterproof_n_data` changes the contest surcharge and so the claim funding
    /// denomination, which is why the value has to be snapshotted per graph rather than computed
    /// once at startup from the node's current params.
    #[test]
    fn claim_funding_value_varies_with_counterproof_n_data() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();

        let mut rolled = (*cfg).clone();
        rolled.game_graph_params.counterproof_n_data = cfg
            .game_graph_params
            .counterproof_n_data
            .checked_add(64)
            .unwrap();

        assert_ne!(
            GraphParams::new(cfg, &ctx).claim_funding_value(),
            GraphParams::new(Arc::new(rolled), &ctx).claim_funding_value(),
        );
    }

    /// The timelocks change the connectors' locking scripts but not their values, so a roll that
    /// only moves timelocks keeps the existing claim-funding pool usable even though it produces
    /// a different claim txid. Pinned because the rollout guidance depends on it.
    #[test]
    fn claim_funding_value_is_independent_of_timelocks() {
        let cfg = test_graph_sm_cfg();
        let ctx = test_graph_sm_ctx();

        let mut rolled = (*cfg).clone();
        rolled.game_graph_params.contest_timelock =
            relative::Height::from_height(cfg.game_graph_params.contest_timelock.value() + 1_000);

        assert_eq!(
            GraphParams::new(cfg, &ctx).claim_funding_value(),
            GraphParams::new(Arc::new(rolled), &ctx).claim_funding_value(),
        );
    }
}
