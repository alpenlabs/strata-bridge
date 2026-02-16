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
                GraphInvalidTransition, INITIAL_BLOCK_HEIGHT, create_sm, get_state,
                test_graph_invalid_transition, test_graph_sm_cfg,
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
    fn test_process_graph_data() {
        let initial_state = GraphState::Created {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        let sm = create_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        seq.process(
            test_graph_sm_cfg(),
            GraphEvent::GraphDataProduced(test_graph_data_event()),
        );

        seq.assert_no_errors();

        // Should transition to GraphGenerated
        assert!(matches!(seq.state(), GraphState::GraphGenerated { .. }));

        // Check that a VerifyAdaptors duty was emitted
        assert!(
            matches!(
                seq.all_duties().as_slice(),
                [GraphDuty::VerifyAdaptors { .. }]
            ),
            "Expected exactly 1 VerifyAdaptors duty to be emitted"
        );
    }

    #[test]
    fn test_duplicate_process_graph_data() {
        let initial_state = GraphState::Created {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        let sm = create_sm(initial_state);
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
