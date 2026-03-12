//! Unit tests for [`StakeSM::process_new_block`].

use super::*;
use crate::stake::{duties::StakeDuty, errors::SSMError, events::NewBlockEvent, state::StakeState};

fn states_with_last_block_height(last_block_height: u64) -> [StakeState; 6] {
    [
        StakeState::Created { last_block_height },
        StakeState::StakeGraphGenerated {
            last_block_height,
            stake_data: TEST_STAKE_DATA.clone(),
            pub_nonces: TEST_PUB_NONCES_MAP.clone(),
        },
        StakeState::UnstakingNoncesCollected {
            last_block_height,
            stake_data: TEST_STAKE_DATA.clone(),
            pub_nonces: TEST_PUB_NONCES_MAP.clone(),
            agg_nonces: TEST_AGG_NONCES.clone(),
            partial_signatures: TEST_PARTIAL_SIGS_MAP.clone(),
        },
        StakeState::UnstakingSigned {
            last_block_height,
            stake_data: TEST_STAKE_DATA.clone(),
            expected_stake_txid: TEST_GRAPH_SUMMARY.stake,
            signatures: TEST_FINAL_SIGS.clone(),
        },
        StakeState::Confirmed {
            last_block_height,
            stake_data: TEST_STAKE_DATA.clone(),
            stake_txid: TEST_GRAPH_SUMMARY.stake,
        },
        StakeState::PreimageRevealed {
            last_block_height,
            stake_data: TEST_STAKE_DATA.clone(),
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
            expected_unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
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
    }
}

#[test]
fn reject_unstaked_state() {
    let from_state = StakeState::Unstaked {
        preimage: TEST_UNSTAKING_PREIMAGE,
        unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
    };
    let expected_state = from_state.clone();
    let mut sm = create_state_machine(from_state);

    let result = sm.process_new_block(
        TEST_CFG.clone(),
        NewBlockEvent {
            block_height: STAKE_HEIGHT + 1,
        },
    );

    assert!(matches!(result, Err(SSMError::Rejected { .. })));
    assert_eq!(sm.state(), &expected_state);
}

#[test]
fn reject_old_height() {
    for old_block_height in [STAKE_HEIGHT - 1, STAKE_HEIGHT] {
        let event = NewBlockEvent {
            block_height: old_block_height,
        };

        for state in states_with_last_block_height(STAKE_HEIGHT) {
            let expected_state = state.clone();
            let mut sm = create_state_machine(state);

            let result = sm.process_new_block(TEST_CFG.clone(), event.clone());

            assert!(matches!(result, Err(SSMError::Rejected { .. })));
            assert_eq!(sm.state(), &expected_state);
        }
    }
}

#[test]
fn accept_new_height() {
    for (from_state, expected_state) in states_with_last_block_height(STAKE_HEIGHT)
        .into_iter()
        .zip(states_with_last_block_height(STAKE_HEIGHT + 1))
    {
        let mut sm = create_state_machine(from_state);

        let output = sm
            .process_new_block(
                TEST_CFG.clone(),
                NewBlockEvent {
                    block_height: STAKE_HEIGHT + 1,
                },
            )
            .expect("new blocks should be accepted");

        assert_eq!(sm.state(), &expected_state);
        assert!(output.duties.is_empty());
        assert!(output.signals.is_empty());
    }
}

#[test]
fn preimage_revealed_timelock_immature() {
    let new_height = UNSTAKING_INTENT_HEIGHT + u64::from(TEST_CFG.unstaking_timelock.value());
    let from_state = preimage_revealed_state(STAKE_HEIGHT, UNSTAKING_INTENT_HEIGHT);
    let expected_state = preimage_revealed_state(new_height, UNSTAKING_INTENT_HEIGHT);
    let mut sm = create_state_machine(from_state);

    let output = sm
        .process_new_block(
            TEST_CFG.clone(),
            NewBlockEvent {
                block_height: new_height,
            },
        )
        .expect("new blocks should be accepted");

    assert_eq!(sm.state(), &expected_state);
    assert!(output.duties.is_empty());
    assert!(output.signals.is_empty());
}

#[test]
fn preimage_revealed_timelock_mature() {
    let new_height = UNSTAKING_INTENT_HEIGHT + TEST_UNSTAKING_TIMELOCK + 1;
    let from_state = preimage_revealed_state(STAKE_HEIGHT, UNSTAKING_INTENT_HEIGHT);
    let expected_state = preimage_revealed_state(new_height, UNSTAKING_INTENT_HEIGHT);
    let mut sm = create_state_machine(from_state);

    let output = sm
        .process_new_block(
            TEST_CFG.clone(),
            NewBlockEvent {
                block_height: new_height,
            },
        )
        .expect("new blocks should be accepted");

    assert_eq!(sm.state(), &expected_state);
    assert_eq!(
        output.duties,
        vec![StakeDuty::PublishUnstakingTx {
            stake_data: TEST_STAKE_DATA.clone(),
        }]
    );
    assert!(output.signals.is_empty());
}
