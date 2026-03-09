//! Unit Tests for process_graph_available
#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use bitcoin::OutPoint;
    use strata_bridge_test_utils::prelude::generate_spending_tx;

    use crate::{
        deposit::{
            duties::DepositDuty,
            errors::DSMError,
            events::{DepositConfirmedEvent, DepositEvent},
            state::DepositState,
            tests::*,
        },
        testing::transition::*,
    };

    /// Tests whether the DepositState transitions to GraphGenerated and produces the expected
    /// PublishDepositNonce duty when processing `GraphAvaileble` messages from all operators in
    /// sequence.
    #[test]
    fn test_process_graph_available_sequence() {
        let deposit_tx = test_deposit_txn();

        let initial_state = DepositState::Created {
            deposit_transaction: deposit_tx.clone(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
            claim_txids: BTreeMap::new(),
        };

        let sm = create_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);
        let mut expected_claim_txids_by_operator = BTreeMap::new();

        for operator_idx in 0..N_TEST_OPERATORS as u32 {
            let claim_txid = generate_txid();
            expected_claim_txids_by_operator.insert(operator_idx, claim_txid);
            seq.process(
                test_deposit_sm_cfg(),
                DepositEvent::GraphMessage(GraphToDeposit::GraphAvailable {
                    claim_txid,
                    operator_idx,
                    deposit_idx: TEST_DEPOSIT_IDX,
                }),
            );
        }

        seq.assert_no_errors();
        let expected_claim_txids: Vec<_> =
            expected_claim_txids_by_operator.values().copied().collect();

        match seq.state() {
            DepositState::GraphGenerated { claim_txids, .. } => {
                assert_eq!(claim_txids, &expected_claim_txids_by_operator);
            }
            _ => panic!("Expected GraphGenerated state"),
        }

        let duties = seq.all_duties();
        assert_eq!(duties.len(), 1, "Expected exactly one duty");
        match duties[0] {
            DepositDuty::PublishDepositNonce { claim_txids, .. } => {
                assert_eq!(claim_txids, &expected_claim_txids);
            }
            _ => panic!("Expected PublishDepositNonce duty"),
        }
    }

    /// Tests whether the DepositState transitions emits a `DSMError::Duplicate` error when
    /// processing duplicate `GraphAvaileble` messages from operators.
    #[test]
    fn test_duplicate_process_graph_available_sequence() {
        let deposit_tx = test_deposit_txn();

        let initial_state = DepositState::Created {
            deposit_transaction: deposit_tx.clone(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
            claim_txids: BTreeMap::new(),
        };

        let sm = create_sm(initial_state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        // Process GraphAvailable messages, all operators except the last one
        for operator_idx in 0..(N_TEST_OPERATORS - 1) as OperatorIdx {
            let event = DepositEvent::GraphMessage(GraphToDeposit::GraphAvailable {
                claim_txid: generate_txid(),
                operator_idx,
                deposit_idx: TEST_DEPOSIT_IDX,
            });
            seq.process(test_deposit_sm_cfg(), event.clone());

            // Process the same event again to simulate duplicate
            test_deposit_invalid_transition(DepositInvalidTransition {
                from_state: seq.state().clone(),
                event,
                expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
            });
        }
    }

    /// tests that a DepositConfirmed event with a deposit tx that doesn't spend the DRT outpoint
    /// is rejected from the DepositPartialsCollected state.
    #[test]
    fn test_deposit_confirmed_wrong_tx_rejection_from_deposit_partials_collected() {
        let deposit_request_outpoint = OutPoint::default();
        let expected_deposit_tx = generate_spending_tx(deposit_request_outpoint, &[]);

        // Create a different transaction (different outpoint)
        let wrong_outpoint = OutPoint::from_str(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:0",
        )
        .unwrap();

        // assert that the deposit request outpoint and the wrong outpoint are not same.
        assert_ne!(
            deposit_request_outpoint, wrong_outpoint,
            "wrong outpoint for test must be different from actual outpoint"
        );

        let wrong_tx = generate_spending_tx(wrong_outpoint, &[]);

        // assert that the deposit tx and the wrong tx for testing are not same.
        assert_ne!(
            expected_deposit_tx, wrong_tx,
            "wrong deposit tx for test must be different from actual deposit tx"
        );

        let state = DepositState::DepositPartialsCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            deposit_transaction: expected_deposit_tx,
        };

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: state,
            event: DepositEvent::DepositConfirmed(DepositConfirmedEvent {
                deposit_transaction: wrong_tx,
            }),
            expected_error: |e| matches!(e, DSMError::Rejected { .. }),
        });
    }

    #[test]
    fn test_invalid_operator_idx_in_process_graph_available() {
        let deposit_tx = test_deposit_txn();

        let initial_state = DepositState::Created {
            deposit_transaction: deposit_tx.clone(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
            claim_txids: BTreeMap::new(),
        };

        let sm = create_sm(initial_state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        // Process GraphAvailable messages with invalid operator idx
        let event = DepositEvent::GraphMessage(GraphToDeposit::GraphAvailable {
            claim_txid: generate_txid(),
            operator_idx: u32::MAX,
            deposit_idx: TEST_DEPOSIT_IDX,
        });
        seq.process(test_deposit_sm_cfg(), event.clone());

        // Process the same event again to simulate duplicate
        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: seq.state().clone(),
            event,
            expected_error: |e| matches!(e, DSMError::Rejected { .. }),
        });
    }

    /// tests that a GraphAvailable event with an invalid deposit_idx is rejected from the Created
    /// state.
    #[test]
    fn test_invalid_deposit_idx_in_process_graph_available() {
        let deposit_tx = test_deposit_txn();
        let initial_state = DepositState::Created {
            deposit_transaction: deposit_tx,
            last_block_height: INITIAL_BLOCK_HEIGHT,
            claim_txids: BTreeMap::new(),
        };

        let invalid_deposit_idx = TEST_DEPOSIT_IDX + 1;
        let event = DepositEvent::GraphMessage(GraphToDeposit::GraphAvailable {
            claim_txid: generate_txid(),
            operator_idx: TEST_ASSIGNEE,
            deposit_idx: invalid_deposit_idx,
        });

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: initial_state,
            event,
            expected_error: |e| matches!(e, DSMError::Rejected { .. }),
        });
    }

    /// tests that a DepositConfirmed event with a deposit tx that doesn't spend the DRT outpoint
    /// is rejected from the DepositNoncesCollected state.
    #[test]
    fn test_deposit_confirmed_wrong_tx_rejection_from_deposit_nonces_collected() {
        let deposit_request_outpoint = OutPoint::default();
        let expected_deposit_tx = generate_spending_tx(deposit_request_outpoint, &[]);

        // Create a different transaction (different outpoint)
        let wrong_outpoint = OutPoint::from_str(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:0",
        )
        .unwrap();

        // assert that the deposit request outpoint and the wrong outpoint are not same.
        assert_ne!(
            deposit_request_outpoint, wrong_outpoint,
            "wrong outpoint for test must be different from actual outpoint"
        );

        let wrong_tx = generate_spending_tx(wrong_outpoint, &[]);

        // assert that the deposit tx and the wrong tx for testing are not same.
        assert_ne!(
            expected_deposit_tx, wrong_tx,
            "wrong deposit tx for test must be different from actual deposit tx"
        );

        let state = DepositState::DepositNoncesCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            deposit_transaction: test_deposit_txn(),
            claim_txids: BTreeMap::new(),
            agg_nonce: generate_agg_nonce(),
            pubnonces: BTreeMap::new(),
            partial_signatures: BTreeMap::new(),
        };

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: state,
            event: DepositEvent::DepositConfirmed(DepositConfirmedEvent {
                deposit_transaction: wrong_tx,
            }),
            expected_error: |e| matches!(e, DSMError::Rejected { .. }),
        });
    }
}
