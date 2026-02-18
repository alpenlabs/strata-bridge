//! Unit Tests for process_deposit_confirmed
#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use bitcoin::{OutPoint, Txid, hashes::Hash};
    use strata_bridge_test_utils::prelude::generate_spending_tx;

    use crate::deposit::{
        errors::DSMError,
        events::{DepositConfirmedEvent, DepositEvent},
        state::DepositState,
        tests::*,
    };

    #[test]
    // tests correct transition from the DepositPartialsCollected to DepositConfirmed state when
    // the DepositConfirmed event is received.
    fn test_deposit_confirmed_from_partials_collected() {
        let deposit_request_outpoint = OutPoint::default();
        let deposit_tx = generate_spending_tx(deposit_request_outpoint, &[]);

        let state = DepositState::DepositPartialsCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            deposit_transaction: deposit_tx.clone(),
        };

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::DepositConfirmed(DepositConfirmedEvent {
                deposit_transaction: deposit_tx,
            }),
            expected_state: DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// tests correct transition from DepositNoncesCollected state to the DepositConfirmed state
    /// when the DepositConfirmed event is received.
    #[test]
    fn test_deposit_confirmed_from_nonces_collected() {
        let deposit_tx = test_deposit_txn();

        let state = DepositState::DepositNoncesCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            deposit_transaction: deposit_tx.clone(),
            pubnonces: BTreeMap::new(),
            agg_nonce: generate_agg_nonce(),
            partial_signatures: BTreeMap::new(),
        };

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::DepositConfirmed(DepositConfirmedEvent {
                deposit_transaction: deposit_tx.as_ref().clone(),
            }),
            expected_state: DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }

    /// tests that all states apart from the DepositNoncesCollected and
    /// DepositPartialsCollected should NOT accept the DepositConfirmed event.
    #[test]
    fn test_deposit_confirmed_invalid_from_other_states() {
        let deposit_request_outpoint = OutPoint::default();
        let tx = generate_spending_tx(deposit_request_outpoint, &[]);
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
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: desc.clone(),
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
                cooperative_payout_tx: test_cooperative_payout_txn(desc.clone()),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payout_tx: test_cooperative_payout_txn(desc.clone()),
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
            test_deposit_invalid_transition(DepositInvalidTransition {
                from_state: state,
                event: DepositEvent::DepositConfirmed(DepositConfirmedEvent {
                    deposit_transaction: tx.clone(),
                }),
                expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
            });
        }
    }
}
