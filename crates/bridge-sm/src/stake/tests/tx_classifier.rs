//! Unit tests for the [`TxClassifier`] implementation on [`StakeSM`].

use bitcoin::OutPoint;
use strata_bridge_test_utils::bitcoin::{generate_spending_tx, generate_txid};

use super::*;
use crate::{stake::events::StakeEvent, tx_classifier::TxClassifier};

const CLASSIFICATION_HEIGHT: u64 = 1337;

fn unstaking_signed_state() -> StakeState {
    StakeState::UnstakingSigned {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        summary: *TEST_GRAPH_SUMMARY,
        signatures: Box::new(*TEST_FINAL_SIGS),
    }
}

fn unstaking_nonces_collected_state() -> StakeState {
    StakeState::UnstakingNoncesCollected {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        summary: *TEST_GRAPH_SUMMARY,
        pub_nonces: TEST_PUB_NONCES_MAP.clone(),
        agg_nonces: TEST_AGG_NONCES.clone().boxed(),
        partial_signatures: TEST_PARTIAL_SIGS_MAP.clone(),
    }
}

fn confirmed_state() -> StakeState {
    StakeState::Confirmed {
        last_block_height: STAKE_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        summary: *TEST_GRAPH_SUMMARY,
        signatures: Some(*TEST_FINAL_SIGS).into(),
    }
}

fn preimage_revealed_state() -> StakeState {
    StakeState::PreimageRevealed {
        last_block_height: UNSTAKING_INTENT_HEIGHT,
        stake_data: TEST_STAKE_DATA.clone(),
        preimage: TEST_UNSTAKING_PREIMAGE,
        unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
        summary: *TEST_GRAPH_SUMMARY,
        signatures: Some(*TEST_FINAL_SIGS).into(),
    }
}

fn all_state_variants() -> Vec<StakeState> {
    vec![
        StakeState::Created {
            last_block_height: STAKE_HEIGHT,
        },
        StakeState::StakeGraphGenerated {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            pub_nonces: TEST_PUB_NONCES_MAP.clone(),
        },
        unstaking_nonces_collected_state(),
        unstaking_signed_state(),
        confirmed_state(),
        preimage_revealed_state(),
        StakeState::Unstaked {
            preimage: TEST_UNSTAKING_PREIMAGE,
            unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
        },
        StakeState::Slashed {
            summary: *TEST_GRAPH_SUMMARY,
            slash_txid: slash_tx().compute_txid(),
            preimage: None,
        },
    ]
}

#[test]
fn classify_stake_tx() {
    for state in [unstaking_nonces_collected_state(), unstaking_signed_state()] {
        let sm = create_state_machine(state.clone());
        let result = sm.classify_tx(&TEST_CFG, TEST_GRAPH.stake.as_ref(), CLASSIFICATION_HEIGHT);

        assert!(
            matches!(result, Some(StakeEvent::StakeConfirmed(_))),
            "expected Some(StakeConfirmed) but got {result:?} in state {state}"
        );
    }
}

#[test]
fn classify_unstaking_intent_tx() {
    let sm = create_state_machine(confirmed_state());
    let result = sm.classify_tx(
        &TEST_CFG,
        TEST_GRAPH.unstaking_intent.as_ref(),
        CLASSIFICATION_HEIGHT,
    );

    match result {
        Some(StakeEvent::PreimageRevealed(event)) => {
            assert_eq!(event.block_height, CLASSIFICATION_HEIGHT);
        }
        _ => panic!("expected Some(PreimageRevealed) but got {result:?}"),
    }
}

#[test]
fn classify_unstaking_tx() {
    let sm = create_state_machine(preimage_revealed_state());
    let result = sm.classify_tx(
        &TEST_CFG,
        TEST_GRAPH.unstaking.as_ref(),
        CLASSIFICATION_HEIGHT,
    );

    assert!(
        matches!(result, Some(StakeEvent::UnstakingConfirmed(_))),
        "expected Some(UnstakingConfirmed) but got {result:?}"
    );
}

#[test]
fn classify_slash_tx() {
    for state in [confirmed_state(), preimage_revealed_state()] {
        let sm = create_state_machine(state.clone());
        let result = sm.classify_tx(&TEST_CFG, &slash_tx(), CLASSIFICATION_HEIGHT);

        assert!(
            matches!(result, Some(StakeEvent::SlashConfirmed(_))),
            "expected Some(SlashConfirmed) but got {result:?} in state {state}"
        );
    }
}

#[test]
fn ignore_irrelevant_tx_in_all_states() {
    let irrelevant_tx = generate_spending_tx(
        OutPoint {
            txid: generate_txid(),
            vout: 0,
        },
        &[],
    );

    for state in all_state_variants() {
        let sm = create_state_machine(state);
        let result = sm.classify_tx(&TEST_CFG, &irrelevant_tx, CLASSIFICATION_HEIGHT);
        assert_eq!(result, None);
    }
}

#[test]
fn ignore_relevant_tx_in_mismatching_states() {
    for state in all_state_variants() {
        let sm = create_state_machine(state.clone());

        let stake_result =
            sm.classify_tx(&TEST_CFG, TEST_GRAPH.stake.as_ref(), CLASSIFICATION_HEIGHT);
        let expect_stake = matches!(
            state,
            StakeState::UnstakingNoncesCollected { .. } | StakeState::UnstakingSigned { .. }
        );
        assert_eq!(
            stake_result.is_some(),
            expect_stake,
            "unexpected stake classification in state {state}"
        );

        let preimage_result = sm.classify_tx(
            &TEST_CFG,
            TEST_GRAPH.unstaking_intent.as_ref(),
            CLASSIFICATION_HEIGHT,
        );
        let expect_preimage = matches!(state, StakeState::Confirmed { .. });
        assert_eq!(
            preimage_result.is_some(),
            expect_preimage,
            "unexpected preimage classification in state {state}"
        );

        let unstaking_result = sm.classify_tx(
            &TEST_CFG,
            TEST_GRAPH.unstaking.as_ref(),
            CLASSIFICATION_HEIGHT,
        );
        let expect_unstaking = matches!(state, StakeState::PreimageRevealed { .. });
        assert_eq!(
            unstaking_result.is_some(),
            expect_unstaking,
            "unexpected unstaking classification in state {state}"
        );

        let slash_result = sm.classify_tx(&TEST_CFG, &slash_tx(), CLASSIFICATION_HEIGHT);
        let expect_slash = matches!(
            state,
            StakeState::Confirmed { .. } | StakeState::PreimageRevealed { .. }
        );
        assert_eq!(
            slash_result.is_some(),
            expect_slash,
            "unexpected slash classification in state {state}"
        );
    }
}
