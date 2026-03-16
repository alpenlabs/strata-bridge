//! Unit tests for [`StakeSM::process_stake_confirmed`].

use super::*;
use crate::stake::{errors::SSMError, events::StakeConfirmedEvent, state::StakeState};

fn signed_state() -> StakeState {
    StakeState::UnstakingSigned {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        expected_stake_txid: TEST_GRAPH_SUMMARY.stake,
        signatures: TEST_FINAL_SIGS.clone(),
    }
}

fn rejected_states() -> [StakeState; 3] {
    [
        StakeState::Created {
            last_block_height: STAKE_HEIGHT,
        },
        StakeState::StakeGraphGenerated {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            pub_nonces: TEST_PUB_NONCES_MAP.clone(),
        },
        StakeState::UnstakingNoncesCollected {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            pub_nonces: TEST_PUB_NONCES_MAP.clone(),
            agg_nonces: TEST_AGG_NONCES.clone(),
            partial_signatures: TEST_PARTIAL_SIGS_MAP.clone(),
        },
    ]
}

fn invalid_states() -> [StakeState; 2] {
    [
        StakeState::PreimageRevealed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
            expected_unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        },
        StakeState::Unstaked {
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        },
    ]
}

#[test]
fn accept_stake_tx() {
    test_stake_transition(StakeTransition {
        from_state: signed_state(),
        event: StakeConfirmedEvent {
            tx: TEST_GRAPH.stake.as_ref().clone(),
        }
        .into(),
        expected_state: StakeState::Confirmed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            stake_txid: TEST_GRAPH_SUMMARY.stake,
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn reject_mismatching_stake_tx() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: signed_state(),
        event: StakeConfirmedEvent {
            tx: TEST_GRAPH.unstaking.as_ref().clone(),
        }
        .into(),
        expected_error: |e| matches!(e, SSMError::Rejected { .. }),
    });
}

#[test]
fn reject_duplicate_stake_confirmed() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: StakeState::Confirmed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            stake_txid: TEST_GRAPH_SUMMARY.stake,
        },
        event: StakeConfirmedEvent {
            tx: TEST_GRAPH.stake.as_ref().clone(),
        }
        .into(),
        expected_error: |e| matches!(e, SSMError::Duplicate { .. }),
    });
}

#[test]
fn reject_invalid_states() {
    for from_state in rejected_states() {
        test_stake_invalid_transition(StakeInvalidTransition {
            from_state,
            event: StakeConfirmedEvent {
                tx: TEST_GRAPH.stake.as_ref().clone(),
            }
            .into(),
            expected_error: |e| matches!(e, SSMError::Rejected { .. }),
        });
    }
}

#[test]
fn reject_invalid_event_after_unstaking_observed() {
    for from_state in invalid_states() {
        test_stake_invalid_transition(StakeInvalidTransition {
            from_state,
            event: StakeConfirmedEvent {
                tx: TEST_GRAPH.stake.as_ref().clone(),
            }
            .into(),
            expected_error: |e| matches!(e, SSMError::InvalidEvent { .. }),
        });
    }
}
