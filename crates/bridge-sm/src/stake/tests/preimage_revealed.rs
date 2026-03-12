//! Unit tests for [`StakeSM::process_preimage_revealed`].

use bitcoin::Transaction;
use strata_bridge_connectors2::prelude::UnstakingIntentWitness;

use super::*;
use crate::stake::{errors::SSMError, events::PreimageRevealedEvent, state::StakeState};

fn confirmed_state() -> StakeState {
    StakeState::Confirmed {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        stake_txid: TEST_GRAPH_SUMMARY.stake,
    }
}

fn revealed_state() -> StakeState {
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
        StakeState::Unstaked {
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        },
    ]
}

fn unstaking_intent_tx() -> Transaction {
    TEST_GRAPH
        .unstaking_intent
        .clone()
        .finalize(&UnstakingIntentWitness {
            n_of_n_signature: TEST_FINAL_SIGS[0],
            unstaking_preimage: TEST_UNSTAKING_PREIMAGE,
        })
}

#[test]
fn accept_preimage_revealed() {
    let from_state = confirmed_state();
    let expected_state = revealed_state();
    let mut sm = create_state_machine(from_state);

    let output = sm
        .process_preimage_revealed(PreimageRevealedEvent {
            tx: unstaking_intent_tx(),
            block_height: UNSTAKING_INTENT_HEIGHT,
        })
        .expect("revealed preimage should be accepted");

    assert_eq!(sm.state(), &expected_state);
    assert!(output.duties.is_empty());
    assert!(output.signals.is_empty());
}

#[test]
fn reject_mismatching_unstaking_intent_tx() {
    let from_state = confirmed_state();
    let expected_state = from_state.clone();
    let mut sm = create_state_machine(from_state);

    let result = sm.process_preimage_revealed(PreimageRevealedEvent {
        tx: TEST_GRAPH.unstaking.as_ref().clone(),
        block_height: UNSTAKING_INTENT_HEIGHT,
    });

    assert!(matches!(result, Err(SSMError::Rejected { .. })));
    assert_eq!(sm.state(), &expected_state);
}

#[test]
fn reject_duplicate_preimage_revealed() {
    let from_state = revealed_state();
    let expected_state = from_state.clone();
    let mut sm = create_state_machine(from_state);

    let result = sm.process_preimage_revealed(PreimageRevealedEvent {
        tx: unstaking_intent_tx(),
        block_height: UNSTAKING_INTENT_HEIGHT + 1,
    });

    assert!(matches!(result, Err(SSMError::Duplicate { .. })));
    assert_eq!(sm.state(), &expected_state);
}

#[test]
fn reject_invalid_states() {
    for from_state in invalid_states() {
        let expected_state = from_state.clone();
        let mut sm = create_state_machine(from_state);

        let result = sm.process_preimage_revealed(PreimageRevealedEvent {
            tx: unstaking_intent_tx(),
            block_height: UNSTAKING_INTENT_HEIGHT,
        });

        assert!(matches!(result, Err(SSMError::InvalidEvent { .. })));
        assert_eq!(sm.state(), &expected_state);
    }
}
