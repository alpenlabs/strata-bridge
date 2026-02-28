//! Unit Tests for process_deposit_signal (CooperativePayoutFailed from Deposit SM)

use strata_bridge_test_utils::bitcoin::generate_txid;

use crate::{
    graph::{
        duties::GraphDuty,
        errors::GSMError,
        events::GraphEvent,
        machine::{GraphSM, generate_game_graph},
        state::GraphState,
        tests::{
            FULFILLMENT_BLOCK_HEIGHT, GraphInvalidTransition, GraphTransition,
            INITIAL_BLOCK_HEIGHT, TEST_POV_IDX, create_nonpov_sm, get_state,
            mock_states::{all_state_variants, fulfilled_state},
            test_deposit_params, test_graph_invalid_transition, test_graph_sm_cfg,
            test_graph_sm_ctx, test_graph_summary,
        },
    },
    signals::DepositToGraph,
    testing::test_transition,
};

fn coop_payout_failed_event() -> GraphEvent {
    GraphEvent::DepositMessage(DepositToGraph::CooperativePayoutFailed {
        assignee: TEST_POV_IDX,
        deposit_idx: Default::default(),
    })
}

#[test]
fn test_coop_payout_failed_from_fulfilled_pov_emits_publish_claim() {
    let cfg = test_graph_sm_cfg();
    let ctx = test_graph_sm_ctx();
    let fulfillment_txid = generate_txid();

    // Generate expected claim tx using the same config and context
    let game_graph = generate_game_graph(&cfg, &ctx, test_deposit_params());

    test_transition::<GraphSM, _, _, _, _, _, _, _>(
        crate::graph::tests::create_sm,
        get_state,
        cfg,
        GraphTransition {
            from_state: fulfilled_state(fulfillment_txid),
            event: coop_payout_failed_event(),
            expected_state: GraphState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                coop_payout_failed: true,
                signatures: Default::default(),
                fulfillment_txid,
                fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
            },
            expected_duties: vec![GraphDuty::PublishClaim {
                claim_tx: game_graph.claim,
            }],
            expected_signals: vec![],
        },
    );
}

#[test]
fn test_coop_payout_failed_from_fulfilled_nonpov_no_duties() {
    let cfg = test_graph_sm_cfg();
    let fulfillment_txid = generate_txid();

    test_transition::<GraphSM, _, _, _, _, _, _, _>(
        create_nonpov_sm,
        get_state,
        cfg,
        GraphTransition {
            from_state: fulfilled_state(fulfillment_txid),
            event: coop_payout_failed_event(),
            expected_state: GraphState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data: test_deposit_params(),
                graph_summary: test_graph_summary(),
                coop_payout_failed: true,
                signatures: Default::default(),
                fulfillment_txid,
                fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        },
    );
}

#[test]
fn test_coop_payout_failed_from_non_fulfilled_states() {
    let non_fulfilled_states: Vec<GraphState> = all_state_variants()
        .into_iter()
        .filter(|s| !matches!(s, GraphState::Fulfilled { .. }))
        .collect();

    for state in non_fulfilled_states {
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: coop_payout_failed_event(),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}
