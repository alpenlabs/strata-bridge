//! Unit tests for [`StakeSM::process_new_block`].

use super::*;
use crate::stake::{duties::StakeDuty, errors::SSMError, events::NewBlockEvent, state::StakeState};

fn states_with_last_block_height(last_block_height: u64) -> [StakeState; 6] {
    [
        StakeState::Created { last_block_height },
        StakeState::StakeGraphGenerated {
            last_block_height,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            pub_nonces: TEST_PUB_NONCES_MAP.clone(),
        },
        StakeState::UnstakingNoncesCollected {
            last_block_height,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            pub_nonces: TEST_PUB_NONCES_MAP.clone(),
            agg_nonces: TEST_AGG_NONCES.clone().boxed(),
            partial_signatures: TEST_PARTIAL_SIGS_MAP.clone(),
        },
        StakeState::UnstakingSigned {
            last_block_height,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            signatures: Box::new(*TEST_FINAL_SIGS),
        },
        StakeState::Confirmed {
            last_block_height,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            signatures: Some(*TEST_FINAL_SIGS).into(),
        },
        StakeState::PreimageRevealed {
            last_block_height,
            stake_data: TEST_STAKE_DATA.clone(),
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
            expected_unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
            signatures: Some(*TEST_FINAL_SIGS).into(),
        },
    ]
}

fn preimage_revealed_state(
    last_block_height: u64,
    unstaking_intent_block_height: u64,
) -> StakeState {
    StakeState::PreimageRevealed {
        last_block_height,
        stake_data: TEST_STAKE_DATA.clone(),
        preimage: TEST_UNSTAKING_PREIMAGE,
        unstaking_intent_block_height,
        expected_unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        signatures: Some(*TEST_FINAL_SIGS).into(),
    }
}

#[test]
fn reject_unstaked_state() {
    let from_state = StakeState::Unstaked {
        preimage: TEST_UNSTAKING_PREIMAGE,
        unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
    };
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state,
        event: NewBlockEvent {
            block_height: STAKE_HEIGHT + 1,
        }
        .into(),
        expected_error: |e| matches!(e, SSMError::Rejected { .. }),
    });
}

#[test]
fn reject_old_height() {
    for old_block_height in [STAKE_HEIGHT - 1, STAKE_HEIGHT] {
        for state in states_with_last_block_height(STAKE_HEIGHT) {
            test_stake_invalid_transition(StakeInvalidTransition {
                from_state: state,
                event: NewBlockEvent {
                    block_height: old_block_height,
                }
                .into(),
                expected_error: |e| matches!(e, SSMError::Rejected { .. }),
            });
        }
    }
}

#[test]
fn accept_new_height() {
    for (from_state, expected_state) in states_with_last_block_height(STAKE_HEIGHT)
        .into_iter()
        .zip(states_with_last_block_height(STAKE_HEIGHT + 1))
    {
        test_stake_transition(StakeTransition {
            from_state,
            event: NewBlockEvent {
                block_height: STAKE_HEIGHT + 1,
            }
            .into(),
            expected_state,
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }
}

#[test]
fn preimage_revealed_timelock_immature() {
    let new_height =
        UNSTAKING_INTENT_HEIGHT + u64::from(TEST_CFG.protocol_params.game_timelock.value());
    let from_state = preimage_revealed_state(STAKE_HEIGHT, UNSTAKING_INTENT_HEIGHT);
    let expected_state = preimage_revealed_state(new_height, UNSTAKING_INTENT_HEIGHT);

    test_stake_transition(StakeTransition {
        from_state,
        event: NewBlockEvent {
            block_height: new_height,
        }
        .into(),
        expected_state,
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn preimage_revealed_timelock_mature() {
    let new_height = UNSTAKING_INTENT_HEIGHT + TEST_UNSTAKING_TIMELOCK + 1;
    let from_state = preimage_revealed_state(STAKE_HEIGHT, UNSTAKING_INTENT_HEIGHT);
    let expected_state = preimage_revealed_state(new_height, UNSTAKING_INTENT_HEIGHT);
    let stake_graph = StakeGraph::new(TEST_STAKE_DATA.clone());
    let unstaking_tx = stake_graph.unstaking.finalize(TEST_FINAL_SIGS.unstaking);
    test_stake_transition(StakeTransition {
        from_state,
        event: NewBlockEvent {
            block_height: new_height,
        }
        .into(),
        expected_state,
        expected_duties: vec![StakeDuty::PublishUnstakingTx {
            signed_tx: unstaking_tx,
        }],
        expected_signals: vec![],
    });
}

#[test]
fn preimage_revealed_timelock_mature_nonpov_no_duty() {
    let new_height = UNSTAKING_INTENT_HEIGHT + TEST_UNSTAKING_TIMELOCK + 1;
    let from_state = StakeState::PreimageRevealed {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        preimage: TEST_UNSTAKING_PREIMAGE,
        unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
        expected_unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        signatures: None.into(),
    };
    let expected_state = StakeState::PreimageRevealed {
        last_block_height: new_height,
        stake_data: TEST_STAKE_DATA.clone(),
        preimage: TEST_UNSTAKING_PREIMAGE,
        unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
        expected_unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        signatures: None.into(),
    };

    test_nonpov_stake_transition(StakeTransition {
        from_state,
        event: NewBlockEvent {
            block_height: new_height,
        }
        .into(),
        expected_state,
        expected_duties: vec![],
        expected_signals: vec![],
    });
}
