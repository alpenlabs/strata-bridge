//! Unit Tests for process_adaptors_verification
#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, num::NonZero};

    use strata_bridge_test_utils::bitcoin::generate_txid;
    use strata_bridge_tx_graph2::game_graph::DepositParams;

    use crate::{
        graph::{
            duties::GraphDuty,
            errors::GSMError,
            events::{AdaptorsVerifiedEvent, GraphEvent},
            state::GraphState,
            tests::{
                GraphInvalidTransition, GraphTransition, INITIAL_BLOCK_HEIGHT, create_sm,
                get_state, test_graph_invalid_transition, test_graph_sm_cfg, test_graph_transition,
                test_sm_ctx,
            },
        },
        testing::EventSequence,
    };

    /// Constructs a valid `GraphGenerated` state directly by generating the graph.
    fn test_graph_generated_state() -> GraphState {
        let cfg = test_graph_sm_cfg();
        let sm = create_sm(GraphState::new(INITIAL_BLOCK_HEIGHT));

        let deposit_params = DepositParams {
            game_index: NonZero::new(1).unwrap(),
            claim_funds: Default::default(),
            deposit_outpoint: sm.context.deposit_outpoint(),
        };
        let graph = sm.generate_graph(&cfg, deposit_params);

        GraphState::GraphGenerated {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: deposit_params,
            graph_summary: graph.summarize(),
        }
    }

    #[test]
    fn test_process_adaptors_verification() {
        let from_state = test_graph_generated_state();

        // Extract fields carried forward into AdaptorsVerified
        let (graph_data, graph_summary) = match &from_state {
            GraphState::GraphGenerated {
                graph_data,
                graph_summary,
                ..
            } => (*graph_data, graph_summary.clone()),
            _ => unreachable!(),
        };

        test_graph_transition(GraphTransition {
            from_state,
            event: GraphEvent::AdaptorsVerified(AdaptorsVerifiedEvent {}),
            expected_state: GraphState::AdaptorsVerified {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                graph_data,
                graph_summary,
                pubnonces: BTreeMap::new(),
            },
            expected_duties: vec![GraphDuty::PublishGraphNonces {
                graph_idx: test_sm_ctx().graph_idx(),
                graph_inpoints: vec![],
                graph_tweaks: vec![],
            }],
            expected_signals: vec![],
        });
    }

    #[test]
    fn test_duplicate_process_adaptors_verification() {
        let sm = create_sm(test_graph_generated_state());
        let mut seq = EventSequence::new(sm, get_state);

        // First event should succeed: GraphGenerated → AdaptorsVerified
        seq.process(
            test_graph_sm_cfg(),
            GraphEvent::AdaptorsVerified(AdaptorsVerifiedEvent {}),
        );
        seq.assert_no_errors();
        assert!(matches!(seq.state(), GraphState::AdaptorsVerified { .. }));

        // Duplicate event from AdaptorsVerified should produce a Duplicate error
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: seq.state().clone(),
            event: GraphEvent::AdaptorsVerified(AdaptorsVerifiedEvent {}),
            expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
        });
    }

    #[test]
    fn test_invalid_process_adaptors_verification_from_withdrawn() {
        // AdaptorsVerified is only valid in GraphGenerated; any other state should be InvalidEvent
        let state = GraphState::Withdrawn {
            payout_txid: generate_txid(),
        };

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::AdaptorsVerified(AdaptorsVerifiedEvent {}),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}
