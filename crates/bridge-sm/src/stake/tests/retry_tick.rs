//! Unit tests for [`StakeSM::process_retry_tick`].

use super::*;
use crate::stake::{duties::StakeDuty, events::RetryTickEvent, state::StakeState};

#[test]
fn retry_publish_stake() {
    let stake_graph = StakeGraph::new(TEST_STAKE_DATA.clone());
    let from_state = StakeState::UnstakingSigned {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        expected_stake_txid: TEST_GRAPH_SUMMARY.stake,
        signatures: TEST_FINAL_SIGS.clone(),
    };
    let expected_state = from_state.clone();

    test_stake_transition(StakeTransition {
        from_state,
        event: RetryTickEvent.into(),
        expected_state,
        expected_duties: vec![StakeDuty::PublishStake {
            tx: stake_graph.stake.as_ref().clone(),
        }],
        expected_signals: vec![],
    });
}

#[test]
fn retry_nothing() {
    let has_no_retriable_duty = [
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
    ];

    for from_state in has_no_retriable_duty {
        let expected_state = from_state.clone();

        test_stake_transition(StakeTransition {
            from_state,
            event: RetryTickEvent.into(),
            expected_state,
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }
}
