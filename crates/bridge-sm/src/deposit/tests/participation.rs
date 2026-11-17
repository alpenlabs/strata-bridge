//! A deposit waiting for a participation decision keeps observing Bitcoin, survives a restart,
//! and cannot be revived once it reaches a terminal state.

use std::collections::BTreeMap;

use bitcoin::OutPoint;
use strata_bridge_test_utils::bitcoin::generate_txid;

use super::{
    INITIAL_BLOCK_HEIGHT, TEST_DEPOSIT_IDX, create_sm, test_deposit_sm_cfg, test_deposit_txn,
};
use crate::{
    deposit::{
        errors::DSMError,
        events::{
            DepositConfirmedEvent, DepositEvent, NagTickEvent, NewBlockEvent, RetryTickEvent,
            SafeHarbourAbortEvent, UserTakeBackEvent,
        },
        machine::DepositSM,
        state::DepositState,
    },
    signals::GraphToDeposit,
    state_machine::StateMachine,
    testing::fixtures::test_takeback_tx,
};

fn pending() -> DepositSM {
    create_sm(DepositState::Created {
        deposit_transaction: test_deposit_txn(),
        claim_txids: BTreeMap::new(),
        last_block_height: INITIAL_BLOCK_HEIGHT,
    })
    .into_participation_pending(vec![])
}

#[test]
fn pending_is_durable_tracks_blocks_and_emits_no_retry_duties() {
    let mut sm = pending();
    for event in [
        DepositEvent::RetryTick(RetryTickEvent),
        DepositEvent::NagTick(NagTickEvent),
        DepositEvent::NewBlock(NewBlockEvent {
            block_height: INITIAL_BLOCK_HEIGHT + 1,
        }),
    ] {
        let output = sm.process_event(test_deposit_sm_cfg(), event).unwrap();
        assert!(output.duties.is_empty());
        assert!(output.signals.is_empty());
    }
    let encoded = postcard::to_allocvec(&sm).unwrap();
    let mut recovered: DepositSM = postcard::from_bytes(&encoded).unwrap();
    assert_eq!(sm, recovered);
    let context = recovered.context().clone();
    assert!(recovered.participate().is_some());
    assert_eq!(recovered.context(), &context);
    assert!(
        matches!(recovered.state(), DepositState::Created { last_block_height, .. } if *last_block_height == INITIAL_BLOCK_HEIGHT + 1)
    );
    assert!(
        recovered.participate().is_none(),
        "participating twice cannot create graphs twice"
    );
}

#[test]
fn events_that_advance_the_deposit_are_rejected_while_pending() {
    for event in [
        DepositEvent::GraphMessage(GraphToDeposit::GraphAvailable {
            claim_txid: generate_txid(),
            operator_idx: 0,
            deposit_idx: TEST_DEPOSIT_IDX,
        }),
        DepositEvent::DepositConfirmed(DepositConfirmedEvent {
            deposit_transaction: test_deposit_txn().as_ref().clone(),
        }),
    ] {
        let mut sm = pending();
        let before = sm.state().clone();
        let err = sm.process_event(test_deposit_sm_cfg(), event).unwrap_err();
        assert!(matches!(err, DSMError::Rejected { .. }), "{err:?}");
        assert_eq!(sm.state(), &before);
    }
}

#[test]
fn refund_and_safe_harbour_abort_cannot_be_revived_by_late_approval() {
    for event in [
        DepositEvent::UserTakeBack(UserTakeBackEvent {
            tx: test_takeback_tx(OutPoint::default()),
        }),
        DepositEvent::SafeHarbourAbort(SafeHarbourAbortEvent),
    ] {
        let mut sm = pending();
        let output = sm.process_event(test_deposit_sm_cfg(), event).unwrap();
        assert!(output.duties.is_empty());
        assert_eq!(sm.state(), &DepositState::Aborted);
        assert!(sm.participate().is_none());
        assert!(!sm.decline_participation());
        assert_eq!(sm.state(), &DepositState::Aborted);
    }
}

#[test]
fn declining_retains_context_and_cannot_be_reopened() {
    let mut sm = pending();
    let context = sm.context().clone();
    assert!(sm.decline_participation());
    assert_eq!(sm.context(), &context);
    assert_eq!(sm.state(), &DepositState::ParticipationDeclined);
    assert!(sm.participate().is_none());
    assert!(
        !sm.decline_participation(),
        "declining twice changes nothing"
    );
}

#[test]
#[should_panic(expected = "only a freshly created deposit request")]
fn only_a_fresh_deposit_request_can_wait_for_a_decision() {
    let _ = pending().into_participation_pending(vec![]);
}
