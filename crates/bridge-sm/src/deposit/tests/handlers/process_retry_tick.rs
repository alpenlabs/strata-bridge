//! Unit tests for process_retry_tick.
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use musig2::AggNonce;

    use crate::deposit::{
        duties::DepositDuty,
        events::{DepositEvent, RetryTickEvent},
        state::DepositState,
        tests::*,
    };

    #[test]
    fn test_retry_tick_emits_publish_deposit_in_deposit_partials_collected() {
        let signed_deposit_transaction = test_deposit_txn().as_ref().clone();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::DepositPartialsCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: signed_deposit_transaction.clone(),
            },
            event: DepositEvent::RetryTick(RetryTickEvent),
            expected_duties: vec![DepositDuty::PublishDeposit {
                signed_deposit_transaction,
            }],
        });
    }

    #[test]
    fn test_retry_tick_emits_fulfill_withdrawal_in_assigned_when_pov_is_assignee() {
        let recipient_desc = random_p2tr_desc();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: recipient_desc.clone(),
            },
            event: DepositEvent::RetryTick(RetryTickEvent),
            expected_duties: vec![DepositDuty::FulfillWithdrawal {
                deposit_idx: TEST_DEPOSIT_IDX,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc,
                deposit_amount: TEST_DEPOSIT_AMOUNT,
            }],
        });
    }

    #[test]
    fn test_retry_tick_emits_request_payout_nonces_in_fulfilled_when_pov_is_assignee() {
        let fulfillment_txid = generate_txid();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX,
                fulfillment_txid,
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            event: DepositEvent::RetryTick(RetryTickEvent),
            expected_duties: vec![DepositDuty::RequestPayoutNonces {
                deposit_idx: TEST_DEPOSIT_IDX,
                pov_operator_idx: TEST_POV_IDX,
            }],
        });
    }

    #[test]
    fn test_retry_tick_noop_in_payout_nonces_collected_when_pov_is_not_assignee() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc);
        let payout_aggregated_nonce =
            AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));

        test_handler_output(DepositHandlerOutput {
            state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_NONPOV_IDX,
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: payout_aggregated_nonce.clone(),
                payout_partial_signatures: BTreeMap::new(),
            },
            event: DepositEvent::RetryTick(RetryTickEvent),
            expected_duties: vec![],
        });
    }

    // ===== Negative POV tests (when POV condition doesn't match → no-op) =====

    #[test]
    fn test_retry_tick_noop_in_assigned_when_pov_is_not_assignee() {
        test_handler_output(DepositHandlerOutput {
            state: DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_NONPOV_IDX, // POV is not the assignee
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: random_p2tr_desc(),
            },
            event: DepositEvent::RetryTick(RetryTickEvent),
            expected_duties: vec![], // No duties when POV is not assignee
        });
    }

    #[test]
    fn test_retry_tick_noop_in_fulfilled_when_pov_is_not_assignee() {
        test_handler_output(DepositHandlerOutput {
            state: DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_NONPOV_IDX, // POV is not the assignee
                fulfillment_txid: generate_txid(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            event: DepositEvent::RetryTick(RetryTickEvent),
            expected_duties: vec![], // No duties when POV is not assignee
        });
    }

    #[test]
    fn test_retry_tick_emits_publish_payout_in_payout_nonces_collected_when_condn_met() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc);
        let payout_aggregated_nonce =
            AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));
        let ordered_pubkeys = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX)
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();
        let mut expected_operators =
            test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX).operator_idxs();
        expected_operators.remove(&TEST_POV_IDX);
        let payout_partial_signatures: BTreeMap<_, _> = expected_operators
            .iter()
            .map(|&idx| (idx, generate_partial_signature()))
            .collect();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX,
                cooperative_payout_tx: cooperative_payout_tx.clone(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: payout_aggregated_nonce.clone(),
                payout_partial_signatures: payout_partial_signatures.clone(),
            },
            event: DepositEvent::RetryTick(RetryTickEvent),
            expected_duties: vec![DepositDuty::PublishPayout {
                deposit_outpoint: test_deposit_outpoint(),
                agg_nonce: payout_aggregated_nonce,
                collected_partials: payout_partial_signatures,
                payout_coop_tx: Box::new(cooperative_payout_tx),
                ordered_pubkeys,
                pov_operator_idx: TEST_POV_IDX,
            }],
        });
    }

    #[test]
    fn test_retry_tick_noop_in_payout_nonces_collected_when_pov_is_assignee_and_missing_partials() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc);
        let payout_aggregated_nonce =
            AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));

        test_handler_output(DepositHandlerOutput {
            state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX,
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce,
                payout_partial_signatures: BTreeMap::new(),
            },
            event: DepositEvent::RetryTick(RetryTickEvent),
            expected_duties: vec![],
        });
    }

    // ===== Non-retriable states (no duties emitted) =====

    #[test]
    fn test_retry_tick_noop_for_non_retriable_states() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc.clone());

        let non_retriable_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
            },
            DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
                pubnonces: BTreeMap::new(),
            },
            DepositState::DepositNoncesCollected {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                pubnonces: BTreeMap::new(),
                claim_txids: BTreeMap::new(),
                agg_nonce: AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce())),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX,
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Spent,
            DepositState::Aborted,
        ];

        for state in non_retriable_states {
            test_handler_output(DepositHandlerOutput {
                state,
                event: DepositEvent::RetryTick(RetryTickEvent),
                expected_duties: vec![],
            });
        }
    }
}
