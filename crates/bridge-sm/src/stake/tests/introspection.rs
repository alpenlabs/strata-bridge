//! Unit tests for introspection methods on [`StakeState`].

use super::*;
use crate::stake::state::StakeState;

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
        summary: *TEST_GRAPH_SUMMARY,
        preimage: TEST_UNSTAKING_PREIMAGE,
        unstaking_intent_block_height: UNSTAKING_INTENT_HEIGHT,
        signatures: Some(*TEST_FINAL_SIGS).into(),
    }
}

fn unstaked_state() -> StakeState {
    StakeState::Unstaked {
        preimage: TEST_UNSTAKING_PREIMAGE,
        unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
    }
}

fn slashed_from_confirmed() -> StakeState {
    StakeState::Slashed {
        summary: *TEST_GRAPH_SUMMARY,
        slash_txid: slash_tx().compute_txid(),
        preimage: None,
    }
}

fn slashed_from_preimage_revealed() -> StakeState {
    StakeState::Slashed {
        summary: *TEST_GRAPH_SUMMARY,
        slash_txid: slash_tx().compute_txid(),
        preimage: Some(TEST_UNSTAKING_PREIMAGE),
    }
}

#[test]
fn is_slashed_only_for_slashed_state() {
    let cases = [
        (confirmed_state(), false),
        (preimage_revealed_state(), false),
        (unstaked_state(), false),
        (slashed_from_confirmed(), true),
        (slashed_from_preimage_revealed(), true),
    ];

    for (state, expected) in cases {
        assert_eq!(
            state.is_slashed(),
            expected,
            "is_slashed mismatch in state {state}"
        );
    }
}

#[test]
fn has_staked_includes_slashed() {
    assert!(slashed_from_confirmed().has_staked());
    assert!(slashed_from_preimage_revealed().has_staked());
}

#[test]
fn is_removed_from_future_covenant_includes_slashed() {
    assert!(slashed_from_confirmed().is_removed_from_future_covenant());
    assert!(slashed_from_preimage_revealed().is_removed_from_future_covenant());
}

#[test]
fn is_stake_available_excludes_slashed() {
    assert!(!slashed_from_confirmed().is_stake_available());
    assert!(!slashed_from_preimage_revealed().is_stake_available());
}

#[test]
fn preimage_returns_none_when_slashed_before_reveal() {
    assert_eq!(slashed_from_confirmed().preimage(), None);
}

#[test]
fn preimage_returned_when_slashed_after_reveal() {
    assert_eq!(
        slashed_from_preimage_revealed().preimage(),
        Some(TEST_UNSTAKING_PREIMAGE)
    );
}

#[test]
fn last_processed_block_height_is_none_in_slashed() {
    assert!(
        slashed_from_confirmed()
            .last_processed_block_height()
            .is_none()
    );
}
