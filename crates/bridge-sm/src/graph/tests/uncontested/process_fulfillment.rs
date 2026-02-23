//! Unit Tests for process_fulfillment
#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::bitcoin::generate_txid;

    use crate::{
        graph::{
            duties::GraphDuty,
            errors::GSMError,
            events::{FulfillmentConfirmedEvent, GraphEvent},
            machine::GraphSM,
            state::GraphState,
            tests::{
                GraphInvalidTransition, GraphTransition, INITIAL_BLOCK_HEIGHT, TEST_POV_IDX,
                create_sm, get_state, test_deposit_params, test_graph_data,
                test_graph_invalid_transition, test_graph_sm_cfg, test_graph_summary,
                test_recipient_desc,
            },
        },
        testing::test_transition,
    };

    /// Block height at which the fulfillment transaction was confirmed.
    const FULFILLMENT_BLOCK_HEIGHT: u64 = 150;
    /// A block height used for assignment deadlines.
    const ASSIGNMENT_DEADLINE: u64 = 200;

    /// Builds a mock `Assigned` state with default test values.
    fn assigned_state() -> GraphState {
        GraphState::Assigned {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            signatures: Default::default(),
            assignee: TEST_POV_IDX,
            deadline: ASSIGNMENT_DEADLINE,
            recipient_desc: test_recipient_desc(1),
        }
    }

    /// Builds a mock `Fulfilled` state with default test values.
    fn fulfilled_state(fulfillment_txid: bitcoin::Txid) -> GraphState {
        GraphState::Fulfilled {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data: test_deposit_params(),
            graph_summary: test_graph_summary(),
            signatures: Default::default(),
            fulfillment_txid,
            fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
        }
    }

    /// Creates a test [`FulfillmentConfirmedEvent`].
    fn test_fulfillment_event() -> FulfillmentConfirmedEvent {
        FulfillmentConfirmedEvent {
            fulfillment_txid: generate_txid(),
            fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
        }
    }

    #[test]
    fn test_fulfillment_from_assigned() {
        let cfg = test_graph_sm_cfg();
        let (_, game_graph) = test_graph_data(&cfg);
        let claim_tx = game_graph.claim.as_ref().clone();

        let event = test_fulfillment_event();
        let fulfillment_txid = event.fulfillment_txid;

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: assigned_state(),
                event: GraphEvent::FulfillmentConfirmed(event),
                expected_state: fulfilled_state(fulfillment_txid),
                expected_duties: vec![GraphDuty::PublishClaim { claim_tx }],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    fn test_duplicate_fulfillment() {
        let fulfillment_txid = generate_txid();

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: fulfilled_state(fulfillment_txid),
            event: GraphEvent::FulfillmentConfirmed(FulfillmentConfirmedEvent {
                fulfillment_txid: generate_txid(),
                fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
            }),
            expected_error: |e| matches!(e, GSMError::Duplicate { .. }),
        });
    }

    #[test]
    fn test_process_fulfillment_from_invalid_state() {
        let state = GraphState::Withdrawn {
            payout_txid: generate_txid(),
        };

        test_graph_invalid_transition(GraphInvalidTransition {
            from_state: state,
            event: GraphEvent::FulfillmentConfirmed(test_fulfillment_event()),
            expected_error: |e| matches!(e, GSMError::InvalidEvent { .. }),
        });
    }
}
