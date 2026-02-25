//! Unit Tests for process_fulfillment
#[cfg(test)]
mod tests {
    use strata_bridge_test_utils::bitcoin::generate_txid;

    use crate::{
        graph::{
            errors::GSMError,
            events::{FulfillmentConfirmedEvent, GraphEvent},
            machine::GraphSM,
            state::GraphState,
            tests::{
                ASSIGNMENT_DEADLINE, FULFILLMENT_BLOCK_HEIGHT, GraphInvalidTransition,
                GraphTransition, TEST_POV_IDX, create_nonpov_sm, create_sm, get_state,
                mock_states::{assigned_state, fulfilled_state},
                test_graph_invalid_transition, test_graph_sm_cfg, test_recipient_desc,
            },
        },
        testing::test_transition,
    };

    /// Creates a test [`FulfillmentConfirmedEvent`].
    pub(super) fn test_fulfillment_event() -> FulfillmentConfirmedEvent {
        FulfillmentConfirmedEvent {
            fulfillment_txid: generate_txid(),
            fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
        }
    }

    #[test]
    fn test_fulfillment_from_assigned() {
        let cfg = test_graph_sm_cfg();

        let event = test_fulfillment_event();
        let fulfillment_txid = event.fulfillment_txid;

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: assigned_state(
                    TEST_POV_IDX,
                    ASSIGNMENT_DEADLINE,
                    test_recipient_desc(1),
                ),
                event: GraphEvent::FulfillmentConfirmed(event),
                expected_state: fulfilled_state(fulfillment_txid),
                expected_duties: vec![],
                expected_signals: vec![],
            },
        );
    }

    #[test]
    fn test_fulfillment_from_assigned_nonpov_no_duty() {
        let cfg = test_graph_sm_cfg();

        let event = test_fulfillment_event();
        let fulfillment_txid = event.fulfillment_txid;

        test_transition::<GraphSM, _, _, _, _, _, _, _>(
            create_nonpov_sm,
            get_state,
            cfg,
            GraphTransition {
                from_state: assigned_state(
                    TEST_POV_IDX,
                    ASSIGNMENT_DEADLINE,
                    test_recipient_desc(1),
                ),
                event: GraphEvent::FulfillmentConfirmed(event),
                expected_state: fulfilled_state(fulfillment_txid),
                expected_duties: vec![],
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
