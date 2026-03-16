//! Unit tests for process_nag_received.
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use musig2::AggNonce;
    use strata_bridge_p2p_types::NagRequestPayload;

    use crate::{
        deposit::{
            duties::DepositDuty,
            errors::DSMError,
            events::{DepositEvent, NagReceivedEvent},
            state::DepositState,
            tests::*,
        },
        testing::fixtures::test_operator_table,
    };

    // ===== Helper to create NagReceivedEvent =====

    fn create_nag_event(payload: NagRequestPayload) -> NagReceivedEvent {
        let sender_idx = TEST_NONPOV_IDX;

        NagReceivedEvent {
            payload,
            sender_operator_idx: sender_idx,
        }
    }

    // ===== Valid nag in correct state tests =====

    #[test]
    fn test_nag_received_deposit_nonce_in_graph_generated_emits_publish_deposit_nonce() {
        let deposit_tx = test_deposit_txn();
        let claim_txids_by_operator: BTreeMap<_, _> = (0..N_TEST_OPERATORS as u32)
            .map(|operator_idx| (operator_idx, generate_txid()))
            .collect();
        let expected_claim_txids: Vec<_> = claim_txids_by_operator.values().copied().collect();
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let ordered_pubkeys: Vec<_> = operator_table
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();

        let signing_info = deposit_tx.signing_info();
        let drt_tweak = signing_info
            .first()
            .expect("deposit tx must have signing info")
            .tweak;

        let expected_duty = DepositDuty::PublishDepositNonce {
            deposit_idx: TEST_DEPOSIT_IDX,
            drt_outpoint: test_deposit_outpoint(),
            claim_txids: expected_claim_txids,
            ordered_pubkeys,
            drt_tweak,
        };

        let nag_event = create_nag_event(NagRequestPayload::DepositNonce {
            deposit_idx: TEST_DEPOSIT_IDX,
        });

        test_handler_output(DepositHandlerOutput {
            state: DepositState::GraphGenerated {
                deposit_transaction: deposit_tx,
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: claim_txids_by_operator,
                pubnonces: BTreeMap::new(),
            },
            event: DepositEvent::NagReceived(nag_event),
            expected_duties: vec![expected_duty],
        });
    }

    #[test]
    fn test_nag_received_deposit_nonce_in_deposit_nonces_collected_emits_publish_deposit_nonce() {
        let deposit_tx = test_deposit_txn();
        let claim_txids_by_operator: BTreeMap<_, _> = (0..N_TEST_OPERATORS as u32)
            .map(|operator_idx| (operator_idx, generate_txid()))
            .collect();
        let expected_claim_txids: Vec<_> = claim_txids_by_operator.values().copied().collect();
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let ordered_pubkeys: Vec<_> = operator_table
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();

        let signing_info = deposit_tx.signing_info();
        let drt_tweak = signing_info
            .first()
            .expect("deposit tx must have signing info")
            .tweak;
        let agg_nonce = AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));

        let expected_duty = DepositDuty::PublishDepositNonce {
            deposit_idx: TEST_DEPOSIT_IDX,
            drt_outpoint: test_deposit_outpoint(),
            claim_txids: expected_claim_txids,
            ordered_pubkeys,
            drt_tweak,
        };

        let nag_event = create_nag_event(NagRequestPayload::DepositNonce {
            deposit_idx: TEST_DEPOSIT_IDX,
        });

        test_handler_output(DepositHandlerOutput {
            state: DepositState::DepositNoncesCollected {
                deposit_transaction: deposit_tx,
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: claim_txids_by_operator,
                agg_nonce,
                pubnonces: BTreeMap::new(),
                partial_signatures: BTreeMap::new(),
            },
            event: DepositEvent::NagReceived(nag_event),
            expected_duties: vec![expected_duty],
        });
    }

    #[test]
    fn test_nag_received_deposit_partial_in_deposit_nonces_collected_emits_publish_deposit_partial()
    {
        let deposit_tx = test_deposit_txn();
        let claim_txids_by_operator: BTreeMap<_, _> = (0..N_TEST_OPERATORS as u32)
            .map(|operator_idx| (operator_idx, generate_txid()))
            .collect();
        let expected_claim_txids: Vec<_> = claim_txids_by_operator.values().copied().collect();
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let ordered_pubkeys: Vec<_> = operator_table
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();

        let signing_info = deposit_tx
            .signing_info()
            .first()
            .copied()
            .expect("deposit tx must have signing info");

        let agg_nonce = AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));

        let expected_duty = DepositDuty::PublishDepositPartial {
            deposit_idx: TEST_DEPOSIT_IDX,
            drt_outpoint: test_deposit_outpoint(),
            claim_txids: expected_claim_txids,
            signing_info,
            deposit_agg_nonce: agg_nonce.clone(),
            ordered_pubkeys,
        };

        let nag_event = create_nag_event(NagRequestPayload::DepositPartial {
            deposit_idx: TEST_DEPOSIT_IDX,
        });

        test_handler_output(DepositHandlerOutput {
            state: DepositState::DepositNoncesCollected {
                deposit_transaction: deposit_tx,
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: claim_txids_by_operator,
                agg_nonce,
                pubnonces: BTreeMap::new(),
                partial_signatures: BTreeMap::new(),
            },
            event: DepositEvent::NagReceived(nag_event),
            expected_duties: vec![expected_duty],
        });
    }

    #[test]
    fn test_nag_received_payout_nonce_in_payout_descriptor_received_emits_publish_payout_nonce() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc);
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let ordered_pubkeys: Vec<_> = operator_table
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();

        let expected_duty = DepositDuty::PublishPayoutNonce {
            deposit_idx: TEST_DEPOSIT_IDX,
            deposit_outpoint: test_deposit_outpoint(),
            ordered_pubkeys,
        };

        let nag_event = create_nag_event(NagRequestPayload::PayoutNonce {
            deposit_idx: TEST_DEPOSIT_IDX,
        });

        test_handler_output(DepositHandlerOutput {
            state: DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                cooperative_payout_tx,
                payout_nonces: BTreeMap::new(),
            },
            event: DepositEvent::NagReceived(nag_event),
            expected_duties: vec![expected_duty],
        });
    }

    #[test]
    fn test_nag_received_payout_nonce_in_payout_nonces_collected_emits_publish_payout_nonce() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc);
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let ordered_pubkeys: Vec<_> = operator_table
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();

        let payout_aggregated_nonce =
            AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));

        let expected_duty = DepositDuty::PublishPayoutNonce {
            deposit_idx: TEST_DEPOSIT_IDX,
            deposit_outpoint: test_deposit_outpoint(),
            ordered_pubkeys,
        };

        let nag_event = create_nag_event(NagRequestPayload::PayoutNonce {
            deposit_idx: TEST_DEPOSIT_IDX,
        });

        test_handler_output(DepositHandlerOutput {
            state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce,
                payout_partial_signatures: BTreeMap::new(),
            },
            event: DepositEvent::NagReceived(nag_event),
            expected_duties: vec![expected_duty],
        });
    }

    #[test]
    fn test_nag_received_payout_partial_in_payout_nonces_collected_emits_publish_payout_partial() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc);
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let ordered_pubkeys: Vec<_> = operator_table
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();

        let payout_aggregated_nonce =
            AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));

        let payout_sighash = cooperative_payout_tx
            .signing_info()
            .first()
            .expect("cooperative payout tx must have signing info")
            .sighash;

        let expected_duty = DepositDuty::PublishPayoutPartial {
            deposit_idx: TEST_DEPOSIT_IDX,
            deposit_outpoint: test_deposit_outpoint(),
            payout_sighash,
            agg_nonce: payout_aggregated_nonce.clone(),
            ordered_pubkeys,
        };

        let nag_event = create_nag_event(NagRequestPayload::PayoutPartial {
            deposit_idx: TEST_DEPOSIT_IDX,
        });

        test_handler_output(DepositHandlerOutput {
            state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_NONPOV_IDX, // POV is not assignee
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce,
                payout_partial_signatures: BTreeMap::new(),
            },
            event: DepositEvent::NagReceived(nag_event),
            expected_duties: vec![expected_duty],
        });
    }

    // ===== Stale/inapplicable nag → rejected =====

    #[test]
    fn test_nag_received_wrong_state_for_nag_type_rejected_with_reason() {
        let nag_event = create_nag_event(NagRequestPayload::DepositNonce {
            deposit_idx: TEST_DEPOSIT_IDX,
        });

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
            },
            event: DepositEvent::NagReceived(nag_event),
            expected_error: |e| {
                matches!(
                    e,
                    DSMError::Rejected { reason, .. }
                        if reason.contains(
                            "expected state(s): GraphGenerated | DepositNoncesCollected"
                        )
                )
            },
        });
    }

    #[test]
    fn test_nag_received_payout_partial_when_pov_is_assignee_rejected_with_reason() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc);
        let payout_aggregated_nonce =
            AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));

        let nag_event = create_nag_event(NagRequestPayload::PayoutPartial {
            deposit_idx: TEST_DEPOSIT_IDX,
        });

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX, // POV IS assignee
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce,
                payout_partial_signatures: BTreeMap::new(),
            },
            event: DepositEvent::NagReceived(nag_event),
            expected_error: |e| {
                matches!(
                    e,
                    DSMError::Rejected { reason, .. }
                        if reason.contains("POV operator")
                            && reason.contains("assignee")
                            && reason.contains("never publishes payout partial")
                )
            },
        });
    }

    #[test]
    fn test_nag_received_deposit_nonce_rejected_in_all_other_states() {
        let recipient_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(recipient_desc.clone());
        let payout_aggregated_nonce =
            AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));

        let invalid_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
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
                recipient_desc: recipient_desc.clone(),
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: generate_txid(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                cooperative_payout_tx: cooperative_payout_tx.clone(),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_NONPOV_IDX,
                cooperative_payout_tx: cooperative_payout_tx.clone(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: payout_aggregated_nonce.clone(),
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
                event: DepositEvent::NagReceived(create_nag_event(
                    NagRequestPayload::DepositNonce {
                        deposit_idx: TEST_DEPOSIT_IDX,
                    },
                )),
                expected_error: |e| matches!(e, DSMError::Rejected { .. }),
            });
        }
    }

    #[test]
    fn test_nag_received_deposit_partial_rejected_in_all_other_states() {
        let recipient_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(recipient_desc.clone());
        let payout_aggregated_nonce =
            AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));

        let invalid_states = [
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
                recipient_desc: recipient_desc.clone(),
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: generate_txid(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                cooperative_payout_tx: cooperative_payout_tx.clone(),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_NONPOV_IDX,
                cooperative_payout_tx: cooperative_payout_tx.clone(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: payout_aggregated_nonce.clone(),
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
                event: DepositEvent::NagReceived(create_nag_event(
                    NagRequestPayload::DepositPartial {
                        deposit_idx: TEST_DEPOSIT_IDX,
                    },
                )),
                expected_error: |e| matches!(e, DSMError::Rejected { .. }),
            });
        }
    }

    #[test]
    fn test_nag_received_payout_nonce_rejected_in_all_other_states() {
        let recipient_desc = random_p2tr_desc();

        let invalid_states = [
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
                claim_txids: BTreeMap::new(),
                agg_nonce: AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce())),
                pubnonces: BTreeMap::new(),
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
                recipient_desc: recipient_desc.clone(),
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: generate_txid(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
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
                event: DepositEvent::NagReceived(create_nag_event(
                    NagRequestPayload::PayoutNonce {
                        deposit_idx: TEST_DEPOSIT_IDX,
                    },
                )),
                expected_error: |e| matches!(e, DSMError::Rejected { .. }),
            });
        }
    }

    #[test]
    fn test_nag_received_payout_partial_rejected_in_all_other_states() {
        let recipient_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(recipient_desc.clone());
        let payout_aggregated_nonce =
            AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));

        let invalid_states = [
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
                claim_txids: BTreeMap::new(),
                agg_nonce: AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce())),
                pubnonces: BTreeMap::new(),
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
                recipient_desc: recipient_desc.clone(),
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                fulfillment_txid: generate_txid(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                cooperative_payout_tx: cooperative_payout_tx.clone(),
                payout_nonces: BTreeMap::new(),
            },
            DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX,
                cooperative_payout_tx: cooperative_payout_tx.clone(),
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce: payout_aggregated_nonce.clone(),
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
                event: DepositEvent::NagReceived(create_nag_event(
                    NagRequestPayload::PayoutPartial {
                        deposit_idx: TEST_DEPOSIT_IDX,
                    },
                )),
                expected_error: |e| matches!(e, DSMError::Rejected { .. }),
            });
        }
    }
}
