//! Unit tests for [`StakeSM::process_stake_data`].

use super::*;
use crate::stake::{
    duties::StakeDuty, errors::SSMError, events::StakeDataReceivedEvent, state::StakeState,
};

fn invalid_states() -> [StakeState; 5] {
    [
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
fn accept_stake_data() {
    test_stake_transition(StakeTransition {
        from_state: StakeState::Created {
            last_block_height: STAKE_HEIGHT,
        },
        event: StakeDataReceivedEvent {
            stake_funds: TEST_STAKE_DATA.setup.stake_funds,
            unstaking_image: TEST_STAKE_DATA.setup.unstaking_image,
            unstaking_output_desc: TEST_STAKE_DATA.setup.unstaking_operator_descriptor.clone(),
        }
        .into(),
        expected_state: StakeState::StakeGraphGenerated {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            pub_nonces: BTreeMap::new(),
        },
        expected_duties: vec![StakeDuty::PublishUnstakingNonces {
            stake_data: TEST_STAKE_DATA.clone(),
        }],
        expected_signals: vec![],
    });
}

#[test]
fn reject_duplicate_data() {
    let setup_params = TEST_STAKE_DATA.setup.clone();
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: StakeState::StakeGraphGenerated {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            pub_nonces: TEST_PUB_NONCES_MAP.clone(),
        },
        event: StakeDataReceivedEvent {
            stake_funds: setup_params.stake_funds,
            unstaking_image: setup_params.unstaking_image,
            unstaking_output_desc: setup_params.unstaking_operator_descriptor,
        }
        .into(),
        expected_error: |e| matches!(e, SSMError::Duplicate { .. }),
    });
}

#[test]
fn reject_invalid_states() {
    let setup_params = TEST_STAKE_DATA.setup.clone();
    for from_state in invalid_states() {
        test_stake_invalid_transition(StakeInvalidTransition {
            from_state,
            event: StakeDataReceivedEvent {
                stake_funds: setup_params.stake_funds,
                unstaking_image: setup_params.unstaking_image,
                unstaking_output_desc: setup_params.unstaking_operator_descriptor.clone(),
            }
            .into(),
            expected_error: |e| matches!(e, SSMError::Rejected { .. }),
        });
    }
}
