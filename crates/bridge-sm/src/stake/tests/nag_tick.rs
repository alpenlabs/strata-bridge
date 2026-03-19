//! Unit tests for [`StakeSM::process_nag_tick`].

use std::collections::BTreeSet;

use super::*;
use crate::stake::{
    duties::{NagDuty, StakeDuty},
    events::NagTickEvent,
    state::StakeState,
};

#[test]
fn nag_stake_data() {
    let from_state = StakeState::Created {
        last_block_height: STAKE_HEIGHT,
    };
    let expected_state = from_state.clone();
    let expected_duties = vec![StakeDuty::Nag(NagDuty::NagStakeData {
        operator_idx: TEST_CTX.operator_idx(),
    })];
    test_stake_transition(StakeTransition {
        from_state,
        event: NagTickEvent.into(),
        expected_state,
        expected_duties,
        expected_signals: vec![],
    });
}

#[test]
fn nag_unstaking_nonces() {
    let pub_nonces = BTreeMap::from([(0, TEST_PUB_NONCES_MAP[&0].clone())]);
    let present: BTreeSet<_> = pub_nonces.keys().copied().collect();
    let expected_duties = TEST_CTX
        .operator_table()
        .operator_idxs()
        .difference(&present)
        .map(|&operator_idx| StakeDuty::Nag(NagDuty::NagUnstakingNonces { operator_idx }))
        .collect::<Vec<_>>();
    let from_state = StakeState::StakeGraphGenerated {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        pub_nonces,
    };
    let expected_state = from_state.clone();
    test_stake_transition(StakeTransition {
        from_state,
        event: NagTickEvent.into(),
        expected_state,
        expected_duties,
        expected_signals: vec![],
    });
}

#[test]
fn nag_unstaking_partials() {
    let partial_signatures = BTreeMap::from([(0, TEST_PARTIAL_SIGS_MAP[&0])]);
    let present: BTreeSet<_> = partial_signatures.keys().copied().collect();
    let expected_duties = TEST_CTX
        .operator_table()
        .operator_idxs()
        .difference(&present)
        .map(|&operator_idx| StakeDuty::Nag(NagDuty::NagUnstakingPartials { operator_idx }))
        .collect::<Vec<_>>();
    let from_state = StakeState::UnstakingNoncesCollected {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        pub_nonces: TEST_PUB_NONCES_MAP.clone(),
        agg_nonces: TEST_AGG_NONCES.clone(),
        partial_signatures,
    };
    let expected_state = from_state.clone();
    test_stake_transition(StakeTransition {
        from_state,
        event: NagTickEvent.into(),
        expected_state,
        expected_duties,
        expected_signals: vec![],
    });
}

#[test]
fn dont_nag_when_nothing_is_missing() {
    let states = [
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
    ];

    for from_state in states {
        let expected_state = from_state.clone();
        test_stake_transition(StakeTransition {
            from_state,
            event: NagTickEvent.into(),
            expected_state,
            expected_duties: vec![],
            expected_signals: vec![],
        });
    }
}
