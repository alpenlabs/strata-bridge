//! Unit Tests for process_graph_data
#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use crate::{
        graph::{
            duties::GraphDuty,
            events::{GraphDataGeneratedEvent, GraphEvent},
            state::GraphState,
            tests::{INITIAL_BLOCK_HEIGHT, create_sm, get_state, test_deposit_sm_cfg},
        },
        testing::EventSequence,
    };

    #[test]
    fn test_process_graph_data() {
        let initial_state = GraphState::Created {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        let graph_data_event = GraphDataGeneratedEvent {
            game_index: NonZero::new(1).unwrap(),
            claim_funds: Default::default(),
        };

        let sm = create_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        seq.process(
            test_deposit_sm_cfg(),
            GraphEvent::GraphDataProduced(graph_data_event.clone()),
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
}
