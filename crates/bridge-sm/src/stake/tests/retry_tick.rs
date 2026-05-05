//! Unit tests for [`StakeSM::process_retry_tick`].

use super::*;
use crate::stake::{duties::StakeDuty, events::RetryTickEvent, state::StakeState};

#[test]
fn retry_publish_stake() {
    let stake_graph = TEST_GRAPH.clone();
    test_pov_owned_handler_output(StakeHandlerOutput {
        state: StakeState::UnstakingSigned {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            signatures: Box::new(*TEST_FINAL_SIGS),
        },
        event: RetryTickEvent.into(),
        expected_duties: vec![StakeDuty::PublishStake {
            operator_idx: TEST_POV_IDX,
            tx: stake_graph.stake.as_ref().clone(),
        }],
    });
}

#[test]
fn retry_nothing_for_foreign_stake() {
    test_nonpov_handler_output(StakeHandlerOutput {
        state: StakeState::UnstakingSigned {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            signatures: Box::new(*TEST_FINAL_SIGS),
        },
        event: RetryTickEvent.into(),
        expected_duties: vec![],
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
            summary: *TEST_GRAPH_SUMMARY,
            pub_nonces: TEST_PUB_NONCES_MAP.clone(),
        },
        StakeState::UnstakingNoncesCollected {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            pub_nonces: TEST_PUB_NONCES_MAP.clone(),
            agg_nonces: TEST_AGG_NONCES.clone().boxed(),
            partial_signatures: TEST_PARTIAL_SIGS_MAP.clone(),
        },
        StakeState::Confirmed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            signatures: Some(*TEST_FINAL_SIGS).into(),
        },
        StakeState::PreimageRevealed {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
            summary: *TEST_GRAPH_SUMMARY,
            signatures: Some(*TEST_FINAL_SIGS).into(),
        },
        StakeState::Unstaked {
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        },
    ];

    for state in has_no_retriable_duty {
        test_pov_owned_handler_output(StakeHandlerOutput {
            state,
            event: RetryTickEvent.into(),
            expected_duties: vec![],
        });
    }
}
