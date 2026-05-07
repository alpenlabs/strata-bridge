//! Unit tests for processing of payout-connector spends.
//!
//! Coverage strategy: a single table-driven test iterates every
//! [`GraphState`] variant returned by [`all_state_variants`] and asserts the
//! outcome of `process_payout_connector_spent` against the per-variant
//! [`expected_outcomes`] mapping. That function uses an exhaustive `match`
//! over [`GraphState`] — adding a new variant is a compile error until the
//! new arm is filled in.
//!
//! Each variant is exercised against four scenarios:
//! - `fresh`: a brand-new spending txid arrives.
//! - `with_stake_pre_set`: `stake_spent` is pre-recorded on the state, then a fresh connector spend
//!   arrives. Skipped for variants that do not carry the field.
//! - `replay_same_txid`: the spending txid matches one already recorded on the state (either via
//!   the `payout_connector_spent` field or via [`AbortReason`]). Skipped where no such record is
//!   possible.
//! - `replay_other_txid`: a *different* spending txid arrives at a state that already has one
//!   recorded.

use bitcoin::{Txid, hashes::Hash};
use strata_bridge_test_utils::bitcoin::generate_txid;

use crate::graph::{
    errors::{GSMError, GSMResult},
    events::PayoutConnectorSpentEvent,
    machine::GSMOutput,
    state::{AbortReason, GraphState},
    tests::{create_sm, mock_states::all_state_variants},
};

fn run(initial: GraphState, spending_txid: Txid) -> GSMResult<(GraphState, GSMOutput)> {
    let mut sm = create_sm(initial);
    let out = sm.process_payout_connector_spent(PayoutConnectorSpentEvent { spending_txid })?;
    Ok((sm.state, out))
}

// ===== Dispatch-table classification =====

#[derive(Debug, Eq, PartialEq, Clone)]
enum Outcome {
    /// Terminal `Aborted` with `reason = PayoutConnectorSpent { spending_txid }`.
    AbortedPayoutConnectorSpent,
    /// Terminal `Aborted` with `reason = Both { ... }` — only reachable when a
    /// post-`Claimed` state already has `stake_spent` set.
    AbortedBoth,
    /// State carries `payout_connector_spent` and we just record the txid.
    RecordsPayoutConnectorSpent,
    /// `GSMError::Rejected`.
    Rejected,
    /// `GSMError::Duplicate`.
    Duplicate,
    /// `GSMError::InvalidEvent`.
    InvalidEvent,
}

#[derive(Debug, Clone)]
struct StateClassification {
    /// Outcome on a fresh spend.
    fresh: Outcome,
    /// Outcome when `stake_spent` is pre-set, then a fresh connector spend
    /// arrives. `None` for states without the field.
    with_stake_pre_set: Option<Outcome>,
    /// Outcome when the spending txid replays one already recorded on the
    /// state (same-txid replay). `None` where no such record is possible.
    replay_same_txid: Option<Outcome>,
    /// Outcome when a connector spend with a *different* txid arrives at a
    /// state that already has one recorded. `None` for variants that
    /// cannot pre-record a connector spend, or where the result is
    /// indistinguishable from `fresh`.
    replay_other_txid: Option<Outcome>,
}

/// Exhaustive over [`GraphState`] — adding a new variant is a compile error.
fn expected_outcomes(state: &GraphState) -> StateClassification {
    match state {
        // Pre-`Claimed`: the connector outpoint does not exist yet, so the
        // classifier should never emit this event from these states. If it
        // does, treat as a protocol breach.
        GraphState::Created { .. }
        | GraphState::GraphGenerated { .. }
        | GraphState::AdaptorsVerified { .. }
        | GraphState::NoncesCollected { .. }
        | GraphState::GraphSigned { .. }
        | GraphState::Assigned { .. }
        | GraphState::Fulfilled { .. } => StateClassification {
            fresh: Outcome::InvalidEvent,
            with_stake_pre_set: None,
            replay_same_txid: None,
            replay_other_txid: None,
        },

        // Two-fact post-`Claimed` states: record the connector spend and
        // stay; abort with `Both` if `stake_spent` is already recorded;
        // matching re-delivery is a duplicate; a different txid arriving
        // after one is recorded is rejected.
        GraphState::Claimed { .. }
        | GraphState::Contested { .. }
        | GraphState::BridgeProofPosted { .. }
        | GraphState::CounterProofPosted { .. } => StateClassification {
            fresh: Outcome::RecordsPayoutConnectorSpent,
            with_stake_pre_set: Some(Outcome::AbortedBoth),
            replay_same_txid: Some(Outcome::Duplicate),
            replay_other_txid: Some(Outcome::Rejected),
        },

        // `AllNackd` direct-aborts: the only remaining payout path uses
        // the connector, so a connector spend makes payout impossible.
        GraphState::AllNackd { .. } => StateClassification {
            fresh: Outcome::AbortedPayoutConnectorSpent,
            with_stake_pre_set: None,
            replay_same_txid: None,
            replay_other_txid: None,
        },

        // `BridgeProofTimedout` / `Acked`: the only remaining path is
        // slash (independent of the connector), so a connector spend is
        // irrelevant and the STF rejects.
        GraphState::BridgeProofTimedout { .. } | GraphState::Acked { .. } => StateClassification {
            fresh: Outcome::Rejected,
            with_stake_pre_set: None,
            replay_same_txid: None,
            replay_other_txid: None,
        },

        // Terminal states: reject all events. `Aborted` with a connector
        // spend recorded in its reason still rejects on replay.
        GraphState::Withdrawn { .. } | GraphState::Slashed { .. } => StateClassification {
            fresh: Outcome::Rejected,
            with_stake_pre_set: None,
            replay_same_txid: None,
            replay_other_txid: None,
        },
        GraphState::Aborted { .. } => StateClassification {
            fresh: Outcome::Rejected,
            with_stake_pre_set: None,
            replay_same_txid: Some(Outcome::Rejected),
            replay_other_txid: None,
        },
    }
}

/// Maps a `process_payout_connector_spent` result to the [`Outcome`] enum
/// used by the dispatch table.
fn outcome_of(initial: &GraphState, result: GSMResult<(GraphState, GSMOutput)>) -> Outcome {
    match result {
        Ok((state, _)) => match state {
            GraphState::Aborted {
                reason: AbortReason::PayoutConnectorSpent { .. },
                ..
            } => Outcome::AbortedPayoutConnectorSpent,
            GraphState::Aborted {
                reason: AbortReason::Both { .. },
                ..
            } => Outcome::AbortedBoth,
            GraphState::Aborted {
                reason: AbortReason::StakeSpent { .. },
                ..
            } => panic!(
                "unexpected post-state: Aborted::StakeSpent (process_payout_connector_spent \
                 should never construct this variant)"
            ),
            other => {
                let mut expected = initial.clone();
                if !expected.set_payout_connector_spent(other.payout_connector_spent_txid().expect(
                    "post-state must record payout_connector_spent for the \
                     RecordsPayoutConnectorSpent branch",
                )) {
                    panic!("initial state does not carry payout_connector_spent");
                }
                assert_eq!(
                    other, expected,
                    "expected only payout_connector_spent to change, got: {other}"
                );
                Outcome::RecordsPayoutConnectorSpent
            }
        },
        Err(GSMError::Duplicate { .. }) => Outcome::Duplicate,
        Err(GSMError::Rejected { .. }) => Outcome::Rejected,
        Err(GSMError::InvalidEvent { .. }) => Outcome::InvalidEvent,
    }
}

/// Prepares a state for the `replay` scenario by ensuring it carries a
/// recorded connector spending txid, then returns the state and that txid.
///
/// For `Aborted::PayoutConnectorSpent` / `Aborted::Both`, the variant
/// already has the txid baked in, so the state is returned unchanged. For
/// two-fact states, `set_payout_connector_spent` records a fixed txid.
fn prepare_replay(variant: GraphState) -> (GraphState, Txid) {
    if let GraphState::Aborted { reason, .. } = &variant {
        match reason {
            AbortReason::PayoutConnectorSpent { spending_txid } => {
                return (variant.clone(), *spending_txid);
            }
            AbortReason::Both {
                payout_connector_spending_txid,
                ..
            } => {
                return (variant.clone(), *payout_connector_spending_txid);
            }
            AbortReason::StakeSpent { .. } => {
                panic!("classifier should not request replay for Aborted::StakeSpent")
            }
        }
    }

    let txid = Txid::from_byte_array([0xef; 32]);
    let mut state = variant;
    assert!(
        state.set_payout_connector_spent(txid),
        "classifier requested replay but state does not carry payout_connector_spent: {state}"
    );
    (state, txid)
}

// ===== The dispatch table test =====

#[test]
fn process_payout_connector_spent_dispatch_table_is_exhaustive() {
    for variant in all_state_variants() {
        let expected = expected_outcomes(&variant);

        // Scenario 1: fresh spend.
        let observed_fresh = outcome_of(&variant, run(variant.clone(), generate_txid()));
        assert_eq!(
            observed_fresh, expected.fresh,
            "fresh-spend outcome mismatch in state {variant}"
        );

        // Scenario 2: stake_spent pre-set, fresh connector spend arrives.
        if let Some(expected) = expected.with_stake_pre_set.clone() {
            let stake_spending_txid = Txid::from_byte_array([0xab; 32]);
            let mut state = variant.clone();
            assert!(
                state.set_stake_spent(stake_spending_txid),
                "with_stake_pre_set is `Some` but state does not carry stake_spent: {variant}"
            );
            let observed = outcome_of(&state, run(state.clone(), generate_txid()));
            assert_eq!(
                observed, expected,
                "with-stake-pre-set outcome mismatch in state {variant}"
            );
        }

        // Scenario 3a: same-txid replay (matches the recorded connector
        // spend).
        if let Some(expected_same) = expected.replay_same_txid.clone() {
            let (state, replay_txid) = prepare_replay(variant.clone());
            let observed = outcome_of(&state, run(state.clone(), replay_txid));
            assert_eq!(
                observed, expected_same,
                "replay (same txid) outcome mismatch in state {variant}"
            );
        }

        // Scenario 3b: a different txid arrives at a state that already
        // has a connector spend recorded.
        if let Some(expected_other) = expected.replay_other_txid.clone() {
            let (state, _) = prepare_replay(variant.clone());
            let observed = outcome_of(&state, run(state.clone(), generate_txid()));
            assert_eq!(
                observed, expected_other,
                "replay (different txid) outcome mismatch in state {variant}"
            );
        }
    }
}
