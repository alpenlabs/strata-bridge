//! Unit tests for process_nag_tick.
#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use strata_bridge_test_utils::bitcoin::generate_txid;

    use crate::{
        graph::{
            duties::{GraphDuty, NagDuty},
            events::{GraphEvent, NagTickEvent},
            machine::GraphSM,
            state::GraphState,
            tests::{
                GraphTransition, INITIAL_BLOCK_HEIGHT, LATER_BLOCK_HEIGHT, N_TEST_OPERATORS,
                TEST_ASSIGNEE, TEST_NONPOV_IDX, TEST_POV_IDX, create_nonpov_sm, get_state,
                test_deposit_params, test_graph_sm_cfg, test_graph_sm_ctx, test_graph_summary,
                test_graph_transition, test_operator_table, test_recipient_desc,
            },
        },
        testing::test_transition,
    };

    // ===== Created state tests (NagGraphData) =====

    #[test]
    fn test_nag_tick_emits_nag_graph_data_for_pov_owned_created_graph() {
        let graph_idx = test_graph_sm_ctx().graph_idx();
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let graph_owner_idx = graph_idx.operator;
        let graph_owner_pubkey = operator_table
            .idx_to_p2p_key(&graph_owner_idx)
            .expect("graph owner idx must be in operator table")
            .clone();

        let state = GraphState::Created {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        test_graph_transition(GraphTransition {
            from_state: state.clone(),
            event: GraphEvent::NagTick(NagTickEvent),
            expected_state: state,
            expected_duties: vec![GraphDuty::Nag {
                duty: NagDuty::NagGraphData {
                    graph_idx,
                    operator_idx: graph_owner_idx,
                    operator_pubkey: graph_owner_pubkey,
                },
            }],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_nag_tick_emits_nag_graph_data_for_nonpov_owned_created_graph() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_NONPOV_IDX);
        let graph_idx = test_graph_sm_ctx().graph_idx();
        let graph_owner_idx = graph_idx.operator;
        let graph_owner_pubkey = operator_table
            .idx_to_p2p_key(&graph_owner_idx)
            .expect("graph owner idx must be in operator table")
            .clone();

        let state = GraphState::Created {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_nonpov_sm,
            get_state,
            test_graph_sm_cfg(),
            GraphTransition {
                from_state: state.clone(),
                event: GraphEvent::NagTick(NagTickEvent),
                expected_state: state,
                expected_duties: vec![GraphDuty::Nag {
                    duty: NagDuty::NagGraphData {
                        graph_idx,
                        operator_idx: graph_owner_idx,
                        operator_pubkey: graph_owner_pubkey,
                    },
                }],
                expected_signals: vec![],
            },
        );
    }

    // ===== AdaptorsVerified state tests (NagGraphNonces) =====

    #[test]
    fn test_nag_tick_emits_nag_graph_nonces_for_missing_operators_in_adaptors_verified() {
        let mut pubnonces = BTreeMap::new();
        pubnonces.insert(TEST_NONPOV_IDX, vec![]);

        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let graph_idx = test_graph_sm_ctx().graph_idx();
        let present: BTreeSet<_> = pubnonces.keys().copied().collect();
        let expected_duties: Vec<GraphDuty> = operator_table
            .operator_idxs()
            .difference(&present)
            .map(|&op_idx| {
                let operator_pubkey = operator_table
                    .idx_to_p2p_key(&op_idx)
                    .expect("operator idx from table must exist")
                    .clone();
                GraphDuty::Nag {
                    duty: NagDuty::NagGraphNonces {
                        graph_idx,
                        operator_idx: op_idx,
                        operator_pubkey,
                    },
                }
            })
            .collect();

        let state = GraphState::AdaptorsVerified {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            pubnonces,
        };

        test_graph_transition(GraphTransition {
            from_state: state.clone(),
            event: GraphEvent::NagTick(NagTickEvent),
            expected_state: state,
            expected_duties,
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_nag_tick_noop_when_all_graph_nonces_present_in_adaptors_verified() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let pubnonces: BTreeMap<_, _> = operator_table
            .operator_idxs()
            .iter()
            .map(|&idx| (idx, vec![]))
            .collect();

        let state = GraphState::AdaptorsVerified {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            pubnonces,
        };

        test_graph_transition(GraphTransition {
            from_state: state.clone(),
            event: GraphEvent::NagTick(NagTickEvent),
            expected_state: state,
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    // ===== NoncesCollected state tests (NagGraphPartials) =====

    #[test]
    fn test_nag_tick_emits_nag_graph_partials_for_missing_operators_in_nonces_collected() {
        let mut partial_signatures = BTreeMap::new();
        partial_signatures.insert(TEST_NONPOV_IDX, vec![]);

        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let graph_idx = test_graph_sm_ctx().graph_idx();
        let present: BTreeSet<_> = partial_signatures.keys().copied().collect();
        let expected_duties: Vec<GraphDuty> = operator_table
            .operator_idxs()
            .difference(&present)
            .map(|&op_idx| {
                let operator_pubkey = operator_table
                    .idx_to_p2p_key(&op_idx)
                    .expect("operator idx from table must exist")
                    .clone();
                GraphDuty::Nag {
                    duty: NagDuty::NagGraphPartials {
                        graph_idx,
                        operator_idx: op_idx,
                        operator_pubkey,
                    },
                }
            })
            .collect();

        let state = GraphState::NoncesCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            pubnonces: BTreeMap::new(),
            agg_nonces: vec![],
            partial_signatures,
        };

        test_graph_transition(GraphTransition {
            from_state: state.clone(),
            event: GraphEvent::NagTick(NagTickEvent),
            expected_state: state,
            expected_duties,
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_nag_tick_noop_when_all_graph_partials_present_in_nonces_collected() {
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let partial_signatures: BTreeMap<_, _> = operator_table
            .operator_idxs()
            .iter()
            .map(|&idx| (idx, vec![]))
            .collect();

        let state = GraphState::NoncesCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            pubnonces: BTreeMap::new(),
            agg_nonces: vec![],
            partial_signatures,
        };

        test_graph_transition(GraphTransition {
            from_state: state.clone(),
            event: GraphEvent::NagTick(NagTickEvent),
            expected_state: state,
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    // ===== Non-naggable states (no duties emitted) =====

    #[test]
    fn test_nag_tick_noop_for_irrelevant_states() {
        let irrelevant_states = vec![
            GraphState::GraphGenerated {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
            },
            GraphState::GraphSigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                agg_nonces: vec![],
                signatures: vec![],
            },
            GraphState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                agg_nonces: vec![],
                signatures: vec![],
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: test_recipient_desc(1),
            },
            GraphState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                coop_payout_failed: false,
                assignee: TEST_ASSIGNEE,
                signatures: vec![],
                fulfillment_txid: generate_txid(),
                fulfillment_block_height: LATER_BLOCK_HEIGHT,
            },
        ];

        for state in irrelevant_states {
            test_graph_transition(GraphTransition {
                from_state: state.clone(),
                event: GraphEvent::NagTick(NagTickEvent),
                expected_state: state,
                expected_duties: vec![],
                expected_signals: vec![],
            });
        }
    }
}
