//! Unit Tests for process_payout_descriptor_received
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use crate::{
        deposit::{
            duties::DepositDuty,
            errors::DSMError,
            events::DepositEvent,
            machine::{COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS, DepositSM},
            state::DepositState,
            tests::*,
        },
        testing::transition::*,
    };

    /// Tests correct transition from Fulfilled to PayoutDescriptorReceived state when
    /// PayoutDescriptorReceived event is received (should emit PublishPayoutNonce duty).
    #[test]
    fn test_payout_descriptor_received_from_fulfilled() {
        let operator_desc = random_p2tr_desc();

        let state = DepositState::Fulfilled {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            fulfillment_txid: generate_txid(),
            fulfillment_height: LATER_BLOCK_HEIGHT,
            cooperative_payout_deadline: LATER_BLOCK_HEIGHT + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
        };

        test_transition::<DepositSM, _, _, _, _, _, _, _>(
            create_sm,
            get_state,
            Transition {
                from_state: state,
                event: DepositEvent::PayoutDescriptorReceived {
                    operator_desc: operator_desc.clone(),
                },
                expected_state: DepositState::PayoutDescriptorReceived {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_ASSIGNEE,
                    cooperative_payment_deadline: LATER_BLOCK_HEIGHT
                        + COOPERATIVE_PAYOUT_TIMEOUT_BLOCKS,
                    operator_desc: operator_desc.clone(),
                    payout_nonces: BTreeMap::new(),
                },
                expected_duties: vec![DepositDuty::PublishPayoutNonce {
                    deposit_outpoint: test_cfg().deposit_outpoint,
                    operator_idx: TEST_ASSIGNEE,
                    operator_desc,
                }],
                expected_signals: vec![],
            },
        );
    }

    /// Tests that all states apart from Fulfilled should NOT accept the PayoutDescriptorReceived
    /// event.
    #[test]
    fn test_payout_descriptor_received_invalid_from_other_states() {
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
            DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc.clone(),
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
                InvalidTransition {
                    from_state: state,
                    event: DepositEvent::PayoutDescriptorReceived {
                        operator_desc: desc.clone(),
                    },
                    expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
                },
            );
        }
    }
}
