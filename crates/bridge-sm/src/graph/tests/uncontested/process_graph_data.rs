//! Unit Tests for process_graph_data
#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use strata_bridge_test_utils::bitcoin::generate_txid;

    use crate::{
        graph::{
            duties::GraphDuty,
            errors::GSMError,
            events::{GraphDataGeneratedEvent, GraphEvent},
            state::GraphState,
            tests::{
                GraphInvalidTransition, INITIAL_BLOCK_HEIGHT, TEST_NONPOV_IDX, create_nonpov_sm,
                create_sm, get_state, test_graph_invalid_transition, test_graph_sm_cfg,
            },
        },
        testing::EventSequence,
    };

    /// Creates a test [`GraphDataGeneratedEvent`] with deterministic values.
    fn test_graph_data_event() -> GraphDataGeneratedEvent {
        GraphDataGeneratedEvent {
            game_index: NonZero::new(1).unwrap(),
            claim_funds: Default::default(),
        }
    }

    #[test]
    fn test_process_graph_data_pov_operator() {
        let initial_state = GraphState::Created {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        // POV operator processing its own graph — no VerifyAdaptors duties expected.
        let sm = create_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        seq.process(
            test_graph_sm_cfg(),
            GraphEvent::GraphDataProduced(test_graph_data_event()),
        );

        seq.assert_no_errors();
        assert!(matches!(seq.state(), GraphState::AdaptorsVerified { .. }));
        assert!(
            matches!(
                seq.all_duties().as_slice(),
                [GraphDuty::PublishGraphNonces { .. }]
            ),
            "Expected exactly 1 PublishGraphNonces duty to be emitted"
        );
    }

    #[test]
    fn test_process_graph_data_nonpov_operator() {
        let initial_state = GraphState::Created {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        // Non-POV operator's graph — VerifyAdaptors duties should be emitted.
        let sm = create_nonpov_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        seq.process(
            test_graph_sm_cfg(),
            GraphEvent::GraphDataProduced(test_graph_data_event()),
        );

        seq.assert_no_errors();
        assert!(matches!(seq.state(), GraphState::GraphGenerated { .. }));

        // Check that a VerifyAdaptors duty was emitted with the correct watchtower index
        assert!(
            matches!(
                seq.all_duties().as_slice(),
                [GraphDuty::VerifyAdaptors { watchtower_idx, .. }] if *watchtower_idx == TEST_NONPOV_IDX
            ),
            "Expected exactly 1 VerifyAdaptors duty with watchtower_idx == TEST_NONPOV_IDX"
        );
    }

    #[test]
    fn test_duplicate_process_pov_graph_data() {
        let initial_state = GraphState::Created {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        let sm = create_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        // First event should succeed: Created → AdaptorsVerified
        seq.process(
            test_graph_sm_cfg(),
            GraphEvent::GraphDataProduced(test_graph_data_event()),
        );
        seq.assert_no_errors();
        assert!(matches!(seq.state(), GraphState::AdaptorsVerified { .. }));

        // Duplicate event from GraphGenerated should produce a Duplicate error
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: seq.state().clone(),
            event: GraphEvent::GraphDataProduced(test_graph_data_event()),
            expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
        });
    }

    #[test]
    fn test_duplicate_process_nonpov_graph_data() {
        let initial_state = GraphState::Created {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        let sm = create_nonpov_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        // First event should succeed: Created → GraphGenerated
        seq.process(
            test_graph_sm_cfg(),
            GraphEvent::GraphDataProduced(test_graph_data_event()),
        );
        seq.assert_no_errors();
        assert!(matches!(seq.state(), GraphState::GraphGenerated { .. }));

        // Duplicate event from GraphGenerated should produce a Duplicate error
        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: seq.state().clone(),
            event: GraphEvent::GraphDataProduced(test_graph_data_event()),
            expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
        });
    }

    #[test]
    fn test_invalid_process_graph_data_from_withdrawn() {
        // GraphDataProduced is only valid in Created; any other state should be InvalidEvent
        let state = GraphState::Withdrawn {
            payout_txid: generate_txid(),
        };

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::GraphDataProduced(test_graph_data_event()),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}
