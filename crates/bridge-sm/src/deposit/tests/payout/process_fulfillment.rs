//! Unit Tests for process_fulfillment
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use bitcoin::{OutPoint, Txid, hashes::Hash};
    use strata_bridge_test_utils::prelude::generate_spending_tx;

    use crate::{
        deposit::{
            duties::DepositDuty,
            errors::DSMError,
            events::{DepositEvent, FulfillmentConfirmedEvent},
            machine::DepositSM,
            state::DepositState,
            tests::*,
        },
        testing::transition::*,
    };

    /// tests correct transition from Assigned to Fulfilled state when FulfillmentConfirmed event
    /// is received and POV operator is the assignee (should emit RequestPayoutNonces duty)
    #[test]
    fn test_fulfillment_confirmed_from_assigned_pov_is_assignee() {
        let fulfillment_tx = generate_spending_tx(OutPoint::default(), &[]);
        let desc = random_p2tr_desc();

        let state = DepositState::Assigned {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_POV_IDX,
            deadline: LATER_BLOCK_HEIGHT,
            recipient_desc: desc,
        };

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            &test_bridge_cfg(),
            Transition {
                from_state: state,
                event: DepositEvent::FulfillmentConfirmed(FulfillmentConfirmedEvent {
                    fulfillment_transaction: fulfillment_tx.clone(),
                    fulfillment_height: LATER_BLOCK_HEIGHT,
                }),
                expected_state: DepositState::Fulfilled {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_POV_IDX,
                    fulfillment_txid: fulfillment_tx.compute_txid(),
                    fulfillment_height: LATER_BLOCK_HEIGHT,
                    cooperative_payout_deadline: LATER_BLOCK_HEIGHT
                        + test_bridge_cfg().cooperative_payout_timeout_blocks(),
                },
                expected_duties: vec![DepositDuty::RequestPayoutNonces {
                    deposit_idx: TEST_DEPOSIT_IDX,
                }],
                expected_signals: vec![],
            },
        );
    }

    /// tests correct transition from Assigned to Fulfilled state when FulfillmentConfirmed event
    /// is received and POV operator is NOT the assignee (should NOT emit any duty).
    #[test]
    fn test_fulfillment_confirmed_from_assigned_pov_is_not_assignee() {
        let fulfillment_tx = generate_spending_tx(OutPoint::default(), &[]);
        let desc = random_p2tr_desc();

        let state = DepositState::Assigned {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_NONPOV_IDX,
            deadline: LATER_BLOCK_HEIGHT,
            recipient_desc: desc,
        };

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            &test_bridge_cfg(),
            Transition {
                from_state: state,
                event: DepositEvent::FulfillmentConfirmed(FulfillmentConfirmedEvent {
                    fulfillment_transaction: fulfillment_tx.clone(),
                    fulfillment_height: LATER_BLOCK_HEIGHT,
                }),
                expected_state: DepositState::Fulfilled {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_NONPOV_IDX,
                    fulfillment_txid: fulfillment_tx.compute_txid(),
                    fulfillment_height: LATER_BLOCK_HEIGHT,
                    cooperative_payout_deadline: LATER_BLOCK_HEIGHT
                        + test_bridge_cfg().cooperative_payout_timeout_blocks(),
                },
                expected_duties: vec![], // No duty since POV is not the assignee
                expected_signals: vec![],
            },
        );
    }

    /// tests that all states apart from Assigned should NOT accept the FulfillmentConfirmed event.
    #[test]
    fn test_fulfillment_confirmed_invalid_from_other_states() {
        let tx = generate_spending_tx(OutPoint::default(), &[]);
        let desc = random_p2tr_desc();

        let invalid_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                linked_graphs: BTreeSet::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
            },
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: Txid::all_zeros(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                operator_desc: desc.clone(),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                operator_desc: desc.clone(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: generate_agg_nonce(),
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Spent,
            DepositState::Aborted,
        ];

        for state in invalid_states {
            test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
                create_sm,
                &test_bridge_cfg(),
                InvalidTransition {
                    from_state: state,
                    event: DepositEvent::FulfillmentConfirmed(FulfillmentConfirmedEvent {
                        fulfillment_transaction: tx.clone(),
                        fulfillment_height: LATER_BLOCK_HEIGHT,
                    }),
                    expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
                },
            );
        }
    }
}
