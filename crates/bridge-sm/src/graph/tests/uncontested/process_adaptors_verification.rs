//! Unit Tests for process_adaptors_verification
#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use strata_bridge_test_utils::bitcoin::generate_txid;
    use strata_bridge_tx_graph2::game_graph::DepositParams;

    use crate::{
        graph::{
            duties::GraphDuty,
            errors::GSMError,
            events::{AdaptorsVerifiedEvent, GraphEvent},
            state::GraphState,
            tests::{
                GraphInvalidTransition, INITIAL_BLOCK_HEIGHT, create_sm, get_state,
                test_graph_invalid_transition, test_graph_sm_cfg,
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
        let state = test_graph_generated_state();
        let sm = create_sm(state);
        let mut seq = EventSequence::new(sm, get_state);

        // GraphGenerated → AdaptorsVerified
        seq.process(
            test_graph_sm_cfg(),
            GraphEvent::AdaptorsVerified(AdaptorsVerifiedEvent {}),
        );
        seq.assert_no_errors();
        assert!(matches!(seq.state(), GraphState::AdaptorsVerified { .. }));

        // Check that a PublishGraphNonces duty was emitted
        assert!(
            matches!(
                seq.all_duties().as_slice(),
                [GraphDuty::PublishGraphNonces { .. }]
            ),
            "Expected exactly 1 PublishGraphNonces duty to be emitted"
        );

        // No signals should be emitted
        assert!(seq.all_signals().is_empty());
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
