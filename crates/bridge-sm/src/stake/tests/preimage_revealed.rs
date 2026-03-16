//! Unit tests for [`StakeSM::process_preimage_revealed`].

use bitcoin::{Transaction, Witness};
use strata_bridge_connectors::prelude::UnstakingIntentWitness;

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
    test_stake_transition(StakeTransition {
        from_state: confirmed_state(),
        event: PreimageRevealedEvent {
            tx: unstaking_intent_tx(),
            block_height: UNSTAKING_INTENT_HEIGHT,
        }
        .into(),
        expected_state: revealed_state(),
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn reject_mismatching_unstaking_intent_tx() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: confirmed_state(),
        event: PreimageRevealedEvent {
            tx: TEST_GRAPH.unstaking.as_ref().clone(),
            block_height: UNSTAKING_INTENT_HEIGHT,
        }
        .into(),
        expected_error: |e| matches!(e, SSMError::InvalidEvent { .. }),
    });
}

#[test]
fn reject_missing_preimage_witness() {
    let mut tx = unstaking_intent_tx();
    tx.input[0].witness = Witness::default();

    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: confirmed_state(),
        event: PreimageRevealedEvent {
            tx,
            block_height: UNSTAKING_INTENT_HEIGHT,
        }
        .into(),
        expected_error: |e| matches!(e, SSMError::InvalidEvent { .. }),
    });
}

#[test]
fn reject_duplicate_preimage_revealed() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: revealed_state(),
        event: PreimageRevealedEvent {
            tx: unstaking_intent_tx(),
            block_height: UNSTAKING_INTENT_HEIGHT + 1,
        }
        .into(),
        expected_error: |e| matches!(e, SSMError::Duplicate { .. }),
    });
}

#[test]
fn reject_invalid_states() {
    for from_state in invalid_states() {
        test_stake_invalid_transition(StakeInvalidTransition {
            from_state,
            event: PreimageRevealedEvent {
                tx: unstaking_intent_tx(),
                block_height: UNSTAKING_INTENT_HEIGHT,
            }
            .into(),
            expected_error: |e| matches!(e, SSMError::Rejected { .. }),
        });
    }
}
