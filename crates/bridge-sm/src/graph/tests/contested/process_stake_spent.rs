//! Unit tests for processing of stake-outpoint spends.
//!
//! Coverage strategy: a single table-driven test iterates every
//! [`GraphState`] variant returned by [`all_state_variants`] and asserts the
//! outcome of `process_stake_spent` against a per-state [`expected_outcomes`] mapping function
//! which uses an exhaustive `match` over [`GraphState`] — adding a new
//! variant is a compile error until the new arm is filled in.

use bitcoin::{OutPoint, Transaction, Txid, hashes::Hash};
use strata_bridge_test_utils::{bitcoin::generate_spending_tx, prelude::generate_txid};

use crate::graph::{
    errors::{GSMError, GSMResult},
    events::StakeSpentEvent,
    machine::GSMOutput,
    state::{AbortReason, GraphState},
    tests::{TestGraphTxKind, create_sm, mock_states::all_state_variants, test_stake_outpoint},
};

// ===== Tx helpers =====

/// A tx that spends the operator's stake outpoint with the *expected* slash
/// txid (i.e. matches `state.expected_slash_txid()` for any state where that
/// helper returns `Some`).
fn matching_slash_tx() -> Transaction {
    TestGraphTxKind::Slash.into()
}

/// A non-slash tx that still consumes the stake outpoint (e.g., a sibling
/// graph's slash or the operator's unstaking).
fn non_matching_stake_spend_tx() -> Transaction {
    let mut tx = generate_spending_tx(test_stake_outpoint(), &[]);
    // Differentiate the txid from `matching_slash_tx()` by adding a junk
    // extra input.
    tx.input.push(bitcoin::TxIn {
        previous_output: OutPoint {
            txid: bitcoin::Txid::all_zeros(),
            vout: u32::MAX,
        },
        ..Default::default()
    });
    tx
}

fn run(initial: GraphState, tx: Transaction) -> GSMResult<(GraphState, GSMOutput)> {
    let mut sm = create_sm(initial);
    let out = sm.process_stake_spent(StakeSpentEvent { tx })?;
    Ok((sm.state, out))
}

// ===== Dispatch-table classification =====

#[derive(Debug, Eq, PartialEq, Clone)]
enum Outcome {
    /// Terminal `Slashed { slash_txid: <spend_txid> }`.
    Slashed,
    /// Terminal `Aborted` with `reason = StakeSpent { spending_txid }`.
    AbortedStakeSpent,
    /// Terminal `Aborted` with `reason = Both { ... }` — only reachable when a
    /// post-`Claimed` state already has `payout_connector_spent` set.
    AbortedBoth,
    /// State carries `stake_spent` and we just record the txid.
    RecordsStakeSpent,
    /// `GSMError::Rejected`.
    Rejected,
    /// `GSMError::Duplicate`.
    Duplicate,
}

#[derive(Debug, Clone)]
struct StateClassification {
    /// Outcome when the spend tx matches `expected_slash_txid()`.
    matching: Outcome,
    /// Outcome when the spend tx does *not* match `expected_slash_txid()`.
    non_matching: Outcome,
    /// `Some(_)` if the state carries `payout_connector_spent`. The contained
    /// outcome describes what happens when that field is pre-set and a
    /// non-matching spend arrives. `None` for states that do not carry the
    /// field.
    with_connector_pre_set: Option<Outcome>,
    /// `Some(_)` if the state carries `stake_spent`. The contained outcome
    /// describes what happens when that field is pre-set with txid `X` and
    /// a stake spend with txid `X` is replayed. `None` for states that do
    /// not carry the field.
    replay_same_txid: Option<Outcome>,
    /// `Some(_)` if the state carries `stake_spent`. The contained outcome
    /// describes what happens when that field is pre-set with txid `X` and
    /// a stake spend with a *different* txid arrives. `None` for states
    /// that do not carry the field.
    replay_other_txid: Option<Outcome>,
}

/// Exhaustive over [`GraphState`] — adding a new variant is a compile error.
fn expected_outcomes(state: &GraphState) -> StateClassification {
    match state {
        // Pre-`NoncesCollected`: no `stake_spent` field, no
        // `expected_slash_txid`. Allowed in protocol but no field to
        // record on.
        GraphState::Created { .. }
        | GraphState::GraphGenerated { .. }
        | GraphState::AdaptorsVerified { .. } => StateClassification {
            matching: Outcome::Rejected,
            non_matching: Outcome::Rejected,
            with_connector_pre_set: None,
            replay_same_txid: None,
            replay_other_txid: None,
        },

        // Signed pre-`Claimed`: `stake_spent` field present,
        // `expected_slash_txid` not yet set. Both branches just record the
        // field.
        GraphState::NoncesCollected { .. }
        | GraphState::GraphSigned { .. }
        | GraphState::Assigned { .. }
        | GraphState::Fulfilled { .. } => StateClassification {
            matching: Outcome::RecordsStakeSpent,
            non_matching: Outcome::RecordsStakeSpent,
            with_connector_pre_set: None,
            replay_same_txid: Some(Outcome::Duplicate),
            replay_other_txid: Some(Outcome::Rejected),
        },

        // Post-`Claimed` two-fact states: `expected_slash_txid` is set;
        // matching → Slashed, non-matching → record the field; if
        // `payout_connector_spent` is pre-set, non-matching aborts with
        // `Both`.
        GraphState::Claimed { .. }
        | GraphState::Contested { .. }
        | GraphState::BridgeProofPosted { .. }
        | GraphState::CounterProofPosted { .. } => StateClassification {
            matching: Outcome::Slashed,
            non_matching: Outcome::RecordsStakeSpent,
            with_connector_pre_set: Some(Outcome::AbortedBoth),
            replay_same_txid: Some(Outcome::Duplicate),
            replay_other_txid: Some(Outcome::Rejected),
        },

        // Only path was slash; non-matching spend means the stake is gone
        // for some other reason → abort directly.
        GraphState::BridgeProofTimedout { .. } | GraphState::Acked { .. } => StateClassification {
            matching: Outcome::Slashed,
            non_matching: Outcome::AbortedStakeSpent,
            with_connector_pre_set: None,
            replay_same_txid: None,
            replay_other_txid: None,
        },

        // Contested payout does not depend on the stake outpoint, so a
        // non-matching spend is irrelevant — rejected, not invalid.
        GraphState::AllNackd { .. } => StateClassification {
            matching: Outcome::Slashed,
            non_matching: Outcome::Rejected,
            with_connector_pre_set: None,
            replay_same_txid: None,
            replay_other_txid: None,
        },

        // Terminal states reject all incoming events.
        GraphState::Withdrawn { .. } | GraphState::Slashed { .. } | GraphState::Aborted { .. } => {
            StateClassification {
                matching: Outcome::Rejected,
                non_matching: Outcome::Rejected,
                with_connector_pre_set: None,
                replay_same_txid: None,
                replay_other_txid: None,
            }
        }
    }
}

/// Maps a `process_stake_spent` result to the [`Outcome`] enum used by the
/// dispatch table. Decodes both the resulting state shape and the error
/// variant.
fn outcome_of(initial: &GraphState, result: GSMResult<(GraphState, GSMOutput)>) -> Outcome {
    match result {
        Ok((state, _)) => {
            match state {
                GraphState::Slashed { .. } => Outcome::Slashed,
                GraphState::Aborted {
                    reason: AbortReason::StakeSpent { .. },
                    ..
                } => Outcome::AbortedStakeSpent,
                GraphState::Aborted {
                    reason: AbortReason::Both { .. },
                    ..
                } => Outcome::AbortedBoth,
                GraphState::Aborted {
                    reason: AbortReason::PayoutConnectorSpent { .. },
                    ..
                } => panic!(
                    "unexpected post-state: Aborted::PayoutConnectorSpent (process_stake_spent \
                 should never construct this variant)"
                ),
                other => {
                    // Asserts the state is unchanged in shape, with stake_spent
                    // recorded. Compare by checking the *other* fields are equal.
                    let mut expected = initial.clone();
                    if !expected.set_stake_spent(other.stake_spent_txid().expect(
                        "post-state must record stake_spent for the RecordsStakeSpent branch",
                    )) {
                        panic!("initial state does not carry stake_spent");
                    }
                    assert_eq!(
                        other, expected,
                        "expected only stake_spent to change, got: {other}"
                    );
                    Outcome::RecordsStakeSpent
                }
            }
        }
        Err(GSMError::Duplicate { .. }) => Outcome::Duplicate,
        Err(GSMError::Rejected { .. }) => Outcome::Rejected,
        Err(GSMError::InvalidEvent { .. }) => panic!(
            "process_stake_spent should not return InvalidEvent; encountered for state {initial}"
        ),
    }
}

// ===== The dispatch table test =====

#[test]
fn process_stake_spent_dispatch_table_is_exhaustive() {
    let matching_tx = matching_slash_tx();
    let non_matching_tx = non_matching_stake_spend_tx();

    // Every variant is exercised below. `all_state_variants()` returns one
    // representative per variant; if a new variant is added the
    // `expected_outcomes` match below fails to compile.
    for variant in all_state_variants() {
        let classification = expected_outcomes(&variant);

        let observed_matching = outcome_of(&variant, run(variant.clone(), matching_tx.clone()));
        assert_eq!(
            observed_matching, classification.matching,
            "matching-branch outcome mismatch in state {variant}"
        );

        let observed_non_matching =
            outcome_of(&variant, run(variant.clone(), non_matching_tx.clone()));
        assert_eq!(
            observed_non_matching, classification.non_matching,
            "non-matching-branch outcome mismatch in state {variant}"
        );

        // Two-fact branch: only post-`Claimed` states with the connector
        // field exercise this. We pre-set the field, then send a
        // non-matching spend.
        if let Some(expected) = classification.with_connector_pre_set.clone() {
            let connector_spending_txid = Txid::from_byte_array([0xcd; 32]);
            let mut state = variant.clone();
            assert!(
                state.set_payout_connector_spent(connector_spending_txid),
                "with_connector_pre_set is `Some` but state does not carry the field: \
                 {variant}"
            );
            let observed_two_fact = outcome_of(&state, run(state.clone(), non_matching_tx.clone()));
            assert_eq!(
                observed_two_fact, expected,
                "two-fact-branch outcome mismatch in state {variant}"
            );
        }

        // Replay branch: pre-set `stake_spent` with the non-matching tx's
        // txid, then re-send the same tx (same-txid replay) and a
        // different tx (different-txid replay). Only states that carry
        // the field exercise these scenarios.
        if let Some(expected_same) = classification.replay_same_txid.clone() {
            let recorded_txid = non_matching_tx.compute_txid();
            let mut state = variant.clone();
            assert!(
                state.set_stake_spent(recorded_txid),
                "replay_same_txid is `Some` but state does not carry stake_spent: \
                 {variant}"
            );
            let observed_replay = outcome_of(&state, run(state.clone(), non_matching_tx.clone()));
            assert_eq!(
                observed_replay, expected_same,
                "replay (same txid) outcome mismatch in state {variant}"
            );
        }
        if let Some(expected_other) = classification.replay_other_txid.clone() {
            // Pre-set with a recorded txid that differs from both
            // `matching_tx` and `non_matching_tx`, then send the
            // non-matching tx (which has a third, different txid).
            let recorded_txid = Txid::from_byte_array([0x77; 32]);
            let mut state = variant.clone();
            assert!(
                state.set_stake_spent(recorded_txid),
                "replay_other_txid is `Some` but state does not carry stake_spent: \
                 {variant}"
            );
            let observed_replay = outcome_of(&state, run(state.clone(), non_matching_tx.clone()));
            assert_eq!(
                observed_replay, expected_other,
                "replay (different txid) outcome mismatch in state {variant}"
            );
        }
    }
}

/// A misrouted/injected event whose tx does not actually spend the stake
/// outpoint must be rejected — it cannot record `stake_spent`, transition
/// to `Slashed`, or terminalize the graph.
#[test]
fn rejects_event_whose_tx_does_not_spend_stake_outpoint() {
    // A tx that consumes some unrelated outpoint, not `test_stake_outpoint()`.
    let random_outpoint = OutPoint {
        txid: generate_txid(),
        vout: 0,
    };
    let unrelated_tx = generate_spending_tx(random_outpoint, &[]);

    for variant in all_state_variants() {
        let observed = outcome_of(&variant, run(variant.clone(), unrelated_tx.clone()));
        assert_eq!(
            observed,
            Outcome::Rejected,
            "expected Rejected for non-stake-spending tx in state {variant}"
        );
    }
}
