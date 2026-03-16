//! Unit tests for [`StakeSM::process_unstaking_partials_received`].

use super::*;
use crate::stake::{errors::SSMError, events::UnstakingPartialsReceivedEvent, state::StakeState};

fn operator_partial_sigs(operator_idx: u32) -> [PartialSignature; StakeGraph::N_MUSIG_INPUTS] {
    TEST_PARTIAL_SIGS_MAP[&operator_idx]
}

fn nonces_collected_state(
    partial_signatures: BTreeMap<u32, [PartialSignature; StakeGraph::N_MUSIG_INPUTS]>,
) -> StakeState {
    StakeState::UnstakingNoncesCollected {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        pub_nonces: TEST_PUB_NONCES_MAP.clone(),
        agg_nonces: TEST_AGG_NONCES.clone(),
        partial_signatures,
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
fn accept_partials() {
    test_stake_transition(StakeTransition {
        from_state: nonces_collected_state(BTreeMap::from([(0, operator_partial_sigs(0))])),
        event: UnstakingPartialsReceivedEvent {
            operator_idx: 1,
            partial_signatures: operator_partial_sigs(1),
        }
        .into(),
        expected_state: nonces_collected_state(BTreeMap::from([
            (0, operator_partial_sigs(0)),
            (1, operator_partial_sigs(1)),
        ])),
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn accept_partials_all_collected() {
    test_stake_transition(StakeTransition {
        from_state: nonces_collected_state(BTreeMap::from([
            (0, operator_partial_sigs(0)),
            (1, operator_partial_sigs(1)),
        ])),
        event: UnstakingPartialsReceivedEvent {
            operator_idx: 2,
            partial_signatures: operator_partial_sigs(2),
        }
        .into(),
        expected_state: StakeState::UnstakingSigned {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            expected_stake_txid: TEST_GRAPH_SUMMARY.stake,
            signatures: TEST_FINAL_SIGS.clone(),
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn reject_invalid_operator() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: nonces_collected_state(BTreeMap::new()),
        event: UnstakingPartialsReceivedEvent {
            operator_idx: 3,
            partial_signatures: operator_partial_sigs(0),
        }
        .into(),
        expected_error: |e| matches!(e, SSMError::Rejected { .. }),
    });
}

#[test]
fn reject_invalid_partials() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: nonces_collected_state(BTreeMap::new()),
        event: UnstakingPartialsReceivedEvent {
            operator_idx: 0,
            partial_signatures: operator_partial_sigs(1),
        }
        .into(),
        expected_error: |e| matches!(e, SSMError::Rejected { .. }),
    });
}

#[test]
fn reject_duplicate_partials() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: nonces_collected_state(BTreeMap::from([(0, operator_partial_sigs(0))])),
        event: UnstakingPartialsReceivedEvent {
            operator_idx: 0,
            partial_signatures: operator_partial_sigs(0),
        }
        .into(),
        expected_error: |e| matches!(e, SSMError::Duplicate { .. }),
    });
}

#[test]
fn reject_duplicate_in_signed_partials() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: StakeState::UnstakingSigned {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            expected_stake_txid: TEST_GRAPH_SUMMARY.stake,
            signatures: TEST_FINAL_SIGS.clone(),
        },
        event: UnstakingPartialsReceivedEvent {
            operator_idx: 0,
            partial_signatures: operator_partial_sigs(0),
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
            event: UnstakingPartialsReceivedEvent {
                operator_idx: 0,
                partial_signatures: operator_partial_sigs(0),
            }
            .into(),
            expected_error: |e| matches!(e, SSMError::Rejected { .. }),
        });
    }
}
