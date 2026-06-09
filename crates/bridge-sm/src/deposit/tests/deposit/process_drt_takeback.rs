//! Unit Tests for process_drt_takeback
#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::OutPoint;
    use strata_bridge_test_utils::musig2::generate_agg_nonce;

    use crate::{
        deposit::{
            errors::DSMError,
            events::{DepositEvent, UserTakeBackEvent},
            state::DepositState,
            tests::*,
        },
        signals::{DepositSignal, DepositToGraph},
        testing::{fixtures::*, transition::*},
    };

    fn deposit_request_taken_back_signal(takeback_txid: bitcoin::Txid) -> DepositSignal {
        DepositSignal::ToGraph(DepositToGraph::DepositRequestTakenBack {
            deposit_idx: TEST_DEPOSIT_IDX,
            takeback_txid,
        })
    }

    #[test]
    fn test_drt_takeback_from_created() {
        let outpoint = OutPoint::default();
        let state = DepositState::Created {
            deposit_transaction: test_deposit_txn(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
            claim_txids: BTreeMap::new(),
        };

        let tx = test_takeback_tx(outpoint);
        let takeback_txid = tx.compute_txid();

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::UserTakeBack(UserTakeBackEvent { tx }),
            expected_state: DepositState::Aborted,
            expected_duties: vec![],
            expected_signals: vec![deposit_request_taken_back_signal(takeback_txid)],
        });
    }

    #[test]
    fn test_drt_takeback_from_graph_generated() {
        let outpoint = OutPoint::default();
        let state = DepositState::GraphGenerated {
            deposit_transaction: test_deposit_txn(),
            claim_txids: BTreeMap::new(),
            pubnonces: Default::default(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        let tx = test_takeback_tx(outpoint);
        let takeback_txid = tx.compute_txid();

        let mut sm = create_sm(state);
        let result = sm.process_drt_takeback(UserTakeBackEvent { tx });

        let output = result.expect("valid DRT takeback must abort DSM");
        assert_eq!(sm.state(), &DepositState::Aborted);
        assert_eq!(output.duties, vec![]);
        assert_eq!(
            output.signals,
            vec![deposit_request_taken_back_signal(takeback_txid)]
        );
    }

    #[test]
    fn test_drt_takeback_from_deposit_nonces_collected() {
        let state = DepositState::DepositNoncesCollected {
            deposit_transaction: test_deposit_txn(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
            claim_txids: BTreeMap::new(),
            agg_nonce: generate_agg_nonce(),
            pubnonces: BTreeMap::new(),
            partial_signatures: BTreeMap::new(),
        };

        let tx = test_takeback_tx(OutPoint::default());
        let takeback_txid = tx.compute_txid();

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::UserTakeBack(UserTakeBackEvent { tx }),
            expected_state: DepositState::Aborted,
            expected_duties: vec![],
            expected_signals: vec![deposit_request_taken_back_signal(takeback_txid)],
        });
    }

    #[test]
    fn test_drt_takeback_from_deposit_partials_collected() {
        let state = DepositState::DepositPartialsCollected {
            deposit_transaction: test_deposit_txn().as_ref().clone(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        let tx = test_takeback_tx(OutPoint::default());
        let takeback_txid = tx.compute_txid();

        test_deposit_transition(DepositTransition {
            from_state: state,
            event: DepositEvent::UserTakeBack(UserTakeBackEvent { tx }),
            expected_state: DepositState::Aborted,
            expected_duties: vec![],
            expected_signals: vec![deposit_request_taken_back_signal(takeback_txid)],
        });
    }

    #[test]
    fn test_drt_takeback_invalid_from_deposited() {
        let state = DepositState::Deposited {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        let tx = test_takeback_tx(OutPoint::default());

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: state,
            event: DepositEvent::UserTakeBack(UserTakeBackEvent { tx }),
            expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
        });
    }

    #[test]
    fn test_drt_takeback_duplicate_in_aborted() {
        let state = DepositState::Aborted;

        let tx = test_takeback_tx(OutPoint::default());

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: state,
            event: DepositEvent::UserTakeBack(UserTakeBackEvent { tx }),
            expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
        });
    }

    #[test]
    fn test_wrong_drt_takeback_tx_rejection() {
        let initial_state = DepositState::Created {
            deposit_transaction: test_deposit_txn(),
            claim_txids: BTreeMap::new(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
        };

        // Run STF with a takeback transaction that does not spend the actual deposit request UTXO
        // (should be rejected)
        let sm = create_sm(initial_state.clone());
        let mut sequence = EventSequence::new(sm, get_state);

        let wrong_outpoint = OutPoint::from_str(
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:0",
        )
        .unwrap();
        let wrong_tx = test_takeback_tx(wrong_outpoint);
        let wrong_tx_event = DepositEvent::UserTakeBack(UserTakeBackEvent { tx: wrong_tx });

        sequence.process(test_deposit_sm_cfg(), wrong_tx_event);

        // Run STF with a takeback transaction that is identical to the deposit request (should
        // also be rejected)
        let duplicate_deposit_txn = test_deposit_txn().as_ref().clone();
        let wrong_spend_path_event = DepositEvent::UserTakeBack(UserTakeBackEvent {
            tx: duplicate_deposit_txn,
        });
        sequence.process(test_deposit_sm_cfg(), wrong_spend_path_event);

        sequence.assert_final_state(&initial_state);

        let errors = sequence.all_errors();
        assert_eq!(
            errors.len(),
            2,
            "Expected 2 errors for 2 events, got {}",
            errors.len()
        );
        errors.iter().for_each(|err| {
            assert!(
                matches!(err, DSMError::Rejected { .. }),
                "Expected Rejected error, got {:?}",
                err
            );
        });
    }
}
