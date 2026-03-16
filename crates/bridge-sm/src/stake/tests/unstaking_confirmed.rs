//! Unit tests for [`StakeSM::process_unstaking_confirmed`].

use bitcoin::Transaction;

use super::*;
use crate::stake::{errors::SSMError, events::UnstakingConfirmedEvent, state::StakeState};

fn preimage_revealed_state() -> StakeState {
    StakeState::PreimageRevealed {
        last_block_height: UNSTAKING_INTENT_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        preimage: TEST_UNSTAKING_PREIMAGE,
        unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
        expected_unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
    }
}

fn invalid_states() -> [StakeState; 5] {
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
        StakeState::UnstakingSigned {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            expected_stake_txid: TEST_GRAPH_SUMMARY.stake,
            signatures: TEST_FINAL_SIGS.clone(),
        },
        StakeState::Confirmed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            stake_txid: TEST_GRAPH_SUMMARY.stake,
        },
    ]
}

fn unstaking_tx() -> Transaction {
    TEST_GRAPH
        .unstaking
        .clone()
        .finalize([TEST_FINAL_SIGS[1], TEST_FINAL_SIGS[2]])
}

#[test]
fn accept_unstaking_tx() {
    test_stake_transition(StakeTransition {
        from_state: preimage_revealed_state(),
        event: UnstakingConfirmedEvent { tx: unstaking_tx() }.into(),
        expected_state: StakeState::Unstaked {
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn reject_mismatching_unstaking_tx() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: preimage_revealed_state(),
        event: UnstakingConfirmedEvent {
            tx: TEST_GRAPH.stake.as_ref().clone(),
        }
        .into(),
        expected_error: |e| matches!(e, SSMError::Rejected { .. }),
    });
}

#[test]
fn reject_duplicate_unstaking_confirmed() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: StakeState::Unstaked {
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        },
        event: UnstakingConfirmedEvent { tx: unstaking_tx() }.into(),
        expected_error: |e| matches!(e, SSMError::Duplicate { .. }),
    });
}

#[test]
fn reject_invalid_states() {
    for from_state in invalid_states() {
        test_stake_invalid_transition(StakeInvalidTransition {
            from_state,
            event: UnstakingConfirmedEvent { tx: unstaking_tx() }.into(),
            expected_error: |e| matches!(e, SSMError::Rejected { .. }),
        });
    }
}
