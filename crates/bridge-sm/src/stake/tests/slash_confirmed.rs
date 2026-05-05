//! Unit tests for [`StakeSM::process_slash_confirmed`].

use bitcoin::{OutPoint, Transaction};
use strata_bridge_test_utils::bitcoin::{generate_spending_tx, generate_txid};
use strata_bridge_tx_graph::transactions::prelude::StakeTx;

use super::*;
use crate::stake::{errors::SSMError, events::SlashConfirmedEvent, state::StakeState};

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

fn invalid_states() -> [StakeState; 4] {
    [
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
        StakeState::UnstakingSigned {
            last_block_height: STAKE_HEIGHT,
            stake_data: TEST_STAKE_DATA.clone(),
            summary: *TEST_GRAPH_SUMMARY,
            signatures: Box::new(*TEST_FINAL_SIGS),
        },
    ]
}

fn slashed_state() -> StakeState {
    StakeState::Slashed {
        summary: *TEST_GRAPH_SUMMARY,
        slash_txid: slash_tx().compute_txid(),
        preimage: None,
    }
}

fn unstaked_state() -> StakeState {
    StakeState::Unstaked {
        preimage: TEST_UNSTAKING_PREIMAGE,
        unstaking_txid: TEST_GRAPH_SUMMARY.unstaking,
    }
}

/// A transaction that spends the stake output of the stake transaction
/// (so it qualifies as a slash transaction).
fn slash_tx() -> Transaction {
    generate_spending_tx(
        OutPoint {
            txid: TEST_GRAPH_SUMMARY.stake,
            vout: StakeTx::STAKE_VOUT,
        },
        // Arbitrary witness data — keeps the txid distinct from the unstaking tx.
        &[vec![0x42]],
    )
}

/// A transaction that does not spend the stake output, so it must not be classified as a slash.
fn non_slash_tx() -> Transaction {
    generate_spending_tx(
        OutPoint {
            txid: generate_txid(),
            vout: 0,
        },
        &[],
    )
}

#[test]
fn accept_slash_from_confirmed() {
    test_stake_transition(StakeTransition {
        from_state: confirmed_state(),
        event: SlashConfirmedEvent { tx: slash_tx() }.into(),
        expected_state: StakeState::Slashed {
            summary: *TEST_GRAPH_SUMMARY,
            slash_txid: slash_tx().compute_txid(),
            preimage: None,
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn accept_slash_from_preimage_revealed() {
    test_stake_transition(StakeTransition {
        from_state: preimage_revealed_state(),
        event: SlashConfirmedEvent { tx: slash_tx() }.into(),
        expected_state: StakeState::Slashed {
            summary: *TEST_GRAPH_SUMMARY,
            slash_txid: slash_tx().compute_txid(),
            preimage: Some(TEST_UNSTAKING_PREIMAGE),
        },
        expected_duties: vec![],
        expected_signals: vec![],
    });
}

#[test]
fn reject_non_slash_tx_in_confirmed() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: confirmed_state(),
        event: SlashConfirmedEvent { tx: non_slash_tx() }.into(),
        expected_error: |e| matches!(e, SSMError::Rejected { .. }),
    });
}

#[test]
fn reject_non_slash_tx_in_preimage_revealed() {
    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: preimage_revealed_state(),
        event: SlashConfirmedEvent { tx: non_slash_tx() }.into(),
        expected_error: |e| matches!(e, SSMError::Rejected { .. }),
    });
}

#[test]
fn reject_unstaking_tx_in_preimage_revealed() {
    // The legitimate unstaking transaction also spends the stake output but must not be
    // classified as a slash.
    let unstaking_tx = TEST_GRAPH
        .unstaking
        .clone()
        .finalize(TEST_FINAL_SIGS.unstaking);

    test_stake_invalid_transition(StakeInvalidTransition {
        from_state: preimage_revealed_state(),
        event: SlashConfirmedEvent { tx: unstaking_tx }.into(),
        expected_error: |e| matches!(e, SSMError::Rejected { .. }),
    });
}

#[test]
fn reject_slash_in_terminal_states() {
    for from_state in [slashed_state(), unstaked_state()] {
        test_stake_invalid_transition(StakeInvalidTransition {
            from_state,
            event: SlashConfirmedEvent { tx: slash_tx() }.into(),
            expected_error: |e| matches!(e, SSMError::Rejected { .. }),
        });
    }
}

#[test]
fn reject_slash_in_invalid_states() {
    for from_state in invalid_states() {
        test_stake_invalid_transition(StakeInvalidTransition {
            from_state,
            event: SlashConfirmedEvent { tx: slash_tx() }.into(),
            expected_error: |e| matches!(e, SSMError::InvalidEvent { .. }),
        });
    }
}
