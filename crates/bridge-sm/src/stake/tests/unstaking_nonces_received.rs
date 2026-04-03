//! Unit tests for [`StakeSM::process_unstaking_nonces_received`].

use super::*;
use crate::{
    stake::{
        duties::StakeDuty, errors::SSMError, events::UnstakingNoncesReceivedEvent,
        state::StakeState,
    },
    testing::EventSequence,
};

fn stake_graph_generated_state(
    pub_nonces: BTreeMap<u32, [PubNonce; StakeGraph::N_MUSIG_INPUTS]>,
) -> StakeState {
    StakeState::StakeGraphGenerated {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        pub_nonces,
    }
}

fn operator_pub_nonces(operator_idx: u32) -> [PubNonce; StakeGraph::N_MUSIG_INPUTS] {
    TEST_PUB_NONCES_MAP[&operator_idx].clone()
}

fn invalid_states() -> [StakeState; 5] {
    [
        StakeState::Created {
            last_block_height: STAKE_HEIGHT,
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
            signatures: TEST_FINAL_SIGS.clone(),
        },
        StakeState::PreimageRevealed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
            expected_unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
            signatures: TEST_FINAL_SIGS.clone(),
        },
        StakeState::Unstaked {
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        },
    ]
}

#[test]
fn accept_nonces() {
    test_stake_transition(StakeTransition {
        from_state: stake_graph_generated_state(BTreeMap::from([(0, operator_pub_nonces(0))])),
        event: UnstakingNoncesReceivedEvent {
            operator_idx: 1,
            pub_nonces: operator_pub_nonces(1).into(),
        }
        .into(),
        expected_state: stake_graph_generated_state(BTreeMap::from([
            (0, operator_pub_nonces(0)),
            (1, operator_pub_nonces(1)),
        ])),
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn accept_nonces_all_collected() {
    let initial_state = stake_graph_generated_state(BTreeMap::from([
        (0, operator_pub_nonces(0)),
        (1, operator_pub_nonces(1)),
    ]));

    let sm = create_state_machine(initial_state);
    let mut seq = EventSequence::new(sm, get_state);

    let nonce_sender = 2;
    let event = UnstakingNoncesReceivedEvent {
        operator_idx: nonce_sender,
        pub_nonces: operator_pub_nonces(nonce_sender).into(),
    }
    .into();

    seq.process(TEST_CFG.clone(), event);

    let new_state = seq.state();
    assert!(
        matches!(new_state, StakeState::UnstakingNoncesCollected { last_block_height, stake_data, pub_nonces, agg_nonces, partial_signatures } if {
            *last_block_height == STAKE_HEIGHT
            && *stake_data == TEST_STAKE_DATA.clone()
            && *pub_nonces ==  TEST_PUB_NONCES_MAP.clone()
            && *agg_nonces == TEST_AGG_NONCES.clone()
            && partial_signatures.is_empty()
        })
    );

    let duties = seq.all_duties();
    assert!(
        matches!(duties.as_slice(), [StakeDuty::PublishUnstakingPartials { operator_idx, agg_nonces, .. }] if {
            *operator_idx == TEST_CTX.operator_idx() && *agg_nonces == TEST_AGG_NONCES.clone()
        })
    );
}

#[test]
fn reject_invalid_operator() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: stake_graph_generated_state(BTreeMap::new()),
        event: UnstakingNoncesReceivedEvent {
            operator_idx: 3,
            pub_nonces: operator_pub_nonces(0).into(),
        }
        .into(),
        expected_error: |e| matches!(e, SSMError::Rejected { .. }),
    });
}

#[test]
fn reject_duplicate_nonces() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: stake_graph_generated_state(BTreeMap::from([(0, operator_pub_nonces(0))])),
        event: UnstakingNoncesReceivedEvent {
            operator_idx: 0,
            pub_nonces: operator_pub_nonces(0).into(),
        }
        .into(),
        expected_error: |e| matches!(e, SSMError::Duplicate { .. }),
    });
}

#[test]
fn reject_duplicate_in_collected_nonces() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: StakeState::UnstakingNoncesCollected {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            pub_nonces: TEST_PUB_NONCES_MAP.clone(),
            agg_nonces: TEST_AGG_NONCES.clone(),
            partial_signatures: BTreeMap::new(),
        },
        event: UnstakingNoncesReceivedEvent {
            operator_idx: 0,
            pub_nonces: operator_pub_nonces(0).into(),
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
            event: UnstakingNoncesReceivedEvent {
                operator_idx: 0,
                pub_nonces: operator_pub_nonces(0).into(),
            }
            .into(),
            expected_error: |e| matches!(e, SSMError::Rejected { .. }),
        });
    }
}
