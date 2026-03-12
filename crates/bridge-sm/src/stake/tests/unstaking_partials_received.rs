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
    let from_state = nonces_collected_state(BTreeMap::from([(0, operator_partial_sigs(0))]));
    let expected_state = nonces_collected_state(BTreeMap::from([
        (0, operator_partial_sigs(0)),
        (1, operator_partial_sigs(1)),
    ]));
    let mut sm = create_state_machine(from_state);

    let output = sm
        .process_unstaking_partials_received(UnstakingPartialsReceivedEvent {
            operator_idx: 1,
            partial_signatures: operator_partial_sigs(1),
        })
        .expect("partials should be accepted");

    assert_eq!(sm.state(), &expected_state);
    assert!(output.duties.is_empty());
    assert!(output.signals.is_empty());
}

#[test]
fn accept_partials_all_collected() {
    let from_state = nonces_collected_state(BTreeMap::from([
        (0, operator_partial_sigs(0)),
        (1, operator_partial_sigs(1)),
    ]));
    let expected_state = StakeState::UnstakingSigned {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        expected_stake_txid: TEST_GRAPH_SUMMARY.stake,
        signatures: TEST_FINAL_SIGS.clone(),
    };
    let mut sm = create_state_machine(from_state);

    let output = sm
        .process_unstaking_partials_received(UnstakingPartialsReceivedEvent {
            operator_idx: 2,
            partial_signatures: operator_partial_sigs(2),
        })
        .expect("final partials should be accepted");

    assert_eq!(sm.state(), &expected_state);
    assert!(output.duties.is_empty());
    assert!(output.signals.is_empty());
}

#[test]
fn reject_invalid_operator() {
    let from_state = nonces_collected_state(BTreeMap::new());
    let expected_state = from_state.clone();
    let mut sm = create_state_machine(from_state);

    let result = sm.process_unstaking_partials_received(UnstakingPartialsReceivedEvent {
        operator_idx: 3,
        partial_signatures: operator_partial_sigs(0),
    });

    assert!(matches!(result, Err(SSMError::Rejected { .. })));
    assert_eq!(sm.state(), &expected_state);
}

#[test]
fn reject_invalid_partials() {
    let from_state = nonces_collected_state(BTreeMap::new());
    let expected_state = from_state.clone();
    let mut sm = create_state_machine(from_state);

    let result = sm.process_unstaking_partials_received(UnstakingPartialsReceivedEvent {
        operator_idx: 0,
        partial_signatures: operator_partial_sigs(1),
    });

    assert!(matches!(result, Err(SSMError::Rejected { .. })));
    assert_eq!(sm.state(), &expected_state);
}

#[test]
fn reject_duplicate_partials() {
    let from_state = nonces_collected_state(BTreeMap::from([(0, operator_partial_sigs(0))]));
    let mut sm = create_state_machine(from_state.clone());

    let result = sm.process_unstaking_partials_received(UnstakingPartialsReceivedEvent {
        operator_idx: 0,
        partial_signatures: operator_partial_sigs(0),
    });

    assert!(matches!(result, Err(SSMError::Duplicate { .. })));
    assert_eq!(sm.state(), &from_state);
}

#[test]
fn reject_duplicate_in_signed_partials() {
    let from_state = StakeState::UnstakingSigned {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        expected_stake_txid: TEST_GRAPH_SUMMARY.stake,
        signatures: TEST_FINAL_SIGS.clone(),
    };
    let mut sm = create_state_machine(from_state.clone());

    let result = sm.process_unstaking_partials_received(UnstakingPartialsReceivedEvent {
        operator_idx: 0,
        partial_signatures: operator_partial_sigs(0),
    });

    assert!(matches!(result, Err(SSMError::Duplicate { .. })));
    assert_eq!(sm.state(), &from_state);
}

#[test]
fn reject_invalid_states() {
    for from_state in invalid_states() {
        let expected_state = from_state.clone();
        let mut sm = create_state_machine(from_state);

        let result = sm.process_unstaking_partials_received(UnstakingPartialsReceivedEvent {
            operator_idx: 0,
            partial_signatures: operator_partial_sigs(0),
        });

        assert!(matches!(result, Err(SSMError::InvalidEvent { .. })));
        assert_eq!(sm.state(), &expected_state);
    }
}
