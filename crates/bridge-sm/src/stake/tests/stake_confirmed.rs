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

fn invalid_states() -> [StakeState; 6] {
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
        StakeState::Confirmed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            stake_txid: TEST_GRAPH_SUMMARY.stake,
        },
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
    let from_state = signed_state();
    let expected_state = StakeState::Confirmed {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        stake_txid: TEST_GRAPH_SUMMARY.stake,
    };
    let mut sm = create_state_machine(from_state);

    let output = sm
        .process_stake_confirmed(StakeConfirmedEvent {
            tx: TEST_GRAPH.stake.as_ref().clone(),
        })
        .expect("stake transaction should be accepted");

    assert_eq!(sm.state(), &expected_state);
    assert!(output.duties.is_empty());
    assert!(output.signals.is_empty());
}

#[test]
fn reject_mismatching_stake_tx() {
    let from_state = signed_state();
    let expected_state = from_state.clone();
    let mut sm = create_state_machine(from_state);

    let result = sm.process_stake_confirmed(StakeConfirmedEvent {
        tx: TEST_GRAPH.unstaking.as_ref().clone(),
    });

    assert!(matches!(result, Err(SSMError::Rejected { .. })));
    assert_eq!(sm.state(), &expected_state);
}

#[test]
fn reject_invalid_states() {
    for from_state in invalid_states() {
        let expected_state = from_state.clone();
        let mut sm = create_state_machine(from_state);

        let result = sm.process_stake_confirmed(StakeConfirmedEvent {
            tx: TEST_GRAPH.stake.as_ref().clone(),
        });

        assert!(matches!(result, Err(SSMError::Rejected { .. })));
        assert_eq!(sm.state(), &expected_state);
    }
}
