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
fn accept_stake_data() {
    let from_state = StakeState::Created {
        last_block_height: STAKE_HEIGHT,
    };
    let expected_state = StakeState::StakeGraphGenerated {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        pub_nonces: BTreeMap::new(),
    };
    let mut sm = create_state_machine(from_state);

    let output = sm
        .process_stake_data(StakeDataReceivedEvent {
            stake_data: TEST_STAKE_DATA.clone(),
        })
        .expect("stake data should be accepted");

    assert_eq!(sm.state(), &expected_state);
    assert_eq!(
        output.duties,
        vec![StakeDuty::PublishUnstakingNonces {
            stake_data: TEST_STAKE_DATA.clone(),
        }]
    );
    assert!(output.signals.is_empty());
}

#[test]
fn reject_duplicate_data() {
    let from_state = StakeState::StakeGraphGenerated {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        pub_nonces: TEST_PUB_NONCES_MAP.clone(),
    };
    let mut sm = create_state_machine(from_state.clone());

    let result = sm.process_stake_data(StakeDataReceivedEvent {
        stake_data: TEST_STAKE_DATA.clone(),
    });

    assert!(matches!(result, Err(SSMError::Duplicate { .. })));
    assert_eq!(sm.state(), &from_state);
}

#[test]
fn reject_invalid_states() {
    for from_state in invalid_states() {
        let expected_state = from_state.clone();
        let mut sm = create_state_machine(from_state);

        let result = sm.process_stake_data(StakeDataReceivedEvent {
            stake_data: TEST_STAKE_DATA.clone(),
        });

        assert!(matches!(result, Err(SSMError::Rejected { .. })));
        assert_eq!(sm.state(), &expected_state);
    }
}
