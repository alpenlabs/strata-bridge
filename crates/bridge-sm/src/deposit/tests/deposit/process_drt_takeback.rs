//! Unit Tests for process_drt_takeback

use std::str::FromStr;

use bitcoin::OutPoint;

use crate::{
    deposit::{
        errors::DSMError,
        events::{DepositEvent, UserTakeBackEvent},
        state::DepositState,
        tests::*,
    },
    testing::{fixtures::*, transition::*},
};

#[test]
fn test_drt_takeback_from_created() {
    let outpoint = OutPoint::default();
    let state = DepositState::Created {
        deposit_transaction: test_deposit_txn(),
        last_block_height: INITIAL_BLOCK_HEIGHT,
        linked_graphs: Default::default(),
    };

    let tx = test_takeback_tx(outpoint);

    test_deposit_transition(DepositTransition {
        from_state: state,
        event: DepositEvent::UserTakeBack(UserTakeBackEvent { tx }),
        expected_state: DepositState::Aborted,
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn test_drt_takeback_from_graph_generated() {
    let outpoint = OutPoint::default();
    let state = DepositState::GraphGenerated {
        deposit_transaction: test_deposit_txn(),
        pubnonces: Default::default(),
        last_block_height: INITIAL_BLOCK_HEIGHT,
    };

    let tx = test_takeback_tx(outpoint);

    let mut sm = create_sm(state);
    let result = sm.process_drt_takeback(UserTakeBackEvent { tx });

    assert!(result.is_ok());
    assert_eq!(sm.state(), &DepositState::Aborted);
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
        linked_graphs: Default::default(),
        last_block_height: INITIAL_BLOCK_HEIGHT,
    };

    // Run STF with a takeback transaction that does not spend the actual deposit request UTXO
    // (should be rejected)
    let sm = create_sm(initial_state.clone());
    let mut sequence = EventSequence::new(sm, get_state);

    let wrong_outpoint =
        OutPoint::from_str("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff:0")
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
