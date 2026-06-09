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
//! - `fresh`: a brand-new spending tx arrives.
//! - `with_stake_pre_set`: `stake_spent` is pre-recorded on the state, then a fresh connector spend
//!   arrives. Skipped for variants that do not carry the field.
//! - `replay_same_txid`: the spending tx is the one whose txid is already recorded on the state
//!   (either via the `payout_connector_spent` field or via [`AbortReason`]). Skipped where no such
//!   record is possible.
//! - `replay_other_txid`: a *different* connector-spending tx arrives at a state that already has
//!   one recorded.

use bitcoin::{OutPoint, Transaction, Txid, hashes::Hash};
use strata_bridge_test_utils::bitcoin::generate_spending_tx;
use strata_bridge_tx_graph::transactions::prelude::ClaimTx;

use crate::graph::{
    errors::{GSMError, GSMResult},
    events::PayoutConnectorSpentEvent,
    machine::GSMOutput,
    state::{AbortReason, GraphState},
    tests::{
        create_sm,
        mock_states::{
            TEST_GRAPH_SUMMARY, all_nackd_state, all_state_variants, bridge_proof_posted_state,
            claimed_state, contested_state, counter_proof_posted_state,
        },
        test_deposit_outpoint,
    },
};

fn run(initial: GraphState, tx: Transaction) -> GSMResult<(GraphState, GSMOutput)> {
    let mut sm = create_sm(initial);
    let out = sm.process_payout_connector_spent(PayoutConnectorSpentEvent { tx })?;
    Ok((sm.state, out))
}

/// The canonical empty-witness tx that consumes the test graph's payout-connector outpoint. Its
/// txid matches the one baked into the `Aborted::PayoutConnectorSpent` mock in `terminal_states`.
fn canonical_connector_spending_tx() -> Transaction {
    generate_spending_tx(
        OutPoint {
            txid: TEST_GRAPH_SUMMARY.claim,
            vout: ClaimTx::PAYOUT_VOUT,
        },
        &[],
    )
}

/// A tx that consumes the connector outpoint and carries a junk extra input with `nonce` as its
/// vout. Distinct nonces produce distinct txids, since txids commit to all non-witness inputs.
fn unique_connector_spending_tx(nonce: u32) -> Transaction {
    let mut tx = canonical_connector_spending_tx();
    tx.input.push(bitcoin::TxIn {
        previous_output: OutPoint {
            txid: Txid::all_zeros(),
            vout: nonce,
        },
        ..Default::default()
    });
    tx
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
    /// Outcome when the spending tx replays one already recorded on the
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
/// recorded connector spending txid, then returns the state and a tx
/// whose computed txid matches that record.
///
/// For `Aborted::PayoutConnectorSpent` / `Aborted::Both`, the variant's
/// recorded txid is the txid of the canonical empty-witness
/// connector-spending tx (see `terminal_states` mock fixture). For
/// two-fact states, we build a tx with a fixed witness and record its
/// txid before returning.
fn prepare_replay(variant: GraphState) -> (GraphState, Transaction) {
    if let GraphState::Aborted { reason, .. } = &variant {
        match reason {
            AbortReason::PayoutConnectorSpent { spending_txid } => {
                let tx = canonical_connector_spending_tx();
                assert_eq!(tx.compute_txid(), *spending_txid);
                return (variant.clone(), tx);
            }
            AbortReason::Both {
                payout_connector_spending_txid,
                ..
            } => {
                let tx = canonical_connector_spending_tx();
                assert_eq!(tx.compute_txid(), *payout_connector_spending_txid);
                return (variant.clone(), tx);
            }
            AbortReason::StakeSpent { .. } => {
                panic!("classifier should not request replay for Aborted::StakeSpent")
            }
            AbortReason::DepositRequestTakenBack { .. } => {
                panic!("classifier should not request replay for Aborted::DepositRequestTakenBack")
            }
        }
    }

    // Two-fact state: build a deterministic tx, record its txid, return both.
    let tx = unique_connector_spending_tx(0xefef);
    let txid = tx.compute_txid();
    let mut state = variant;
    assert!(
        state.set_payout_connector_spent(txid),
        "classifier requested replay but state does not carry payout_connector_spent: {state}"
    );
    (state, tx)
}

// ===== The dispatch table test =====

#[test]
fn process_payout_connector_spent_dispatch_table_is_exhaustive() {
    // Distinct nonce vouts per scenario produce distinct txids so the
    // fresh, with-stake, and replay-other cases do not collide with the
    // recorded txid set up in `prepare_replay`.
    let fresh_tx = unique_connector_spending_tx(0x01);
    let fresh_with_stake_tx = unique_connector_spending_tx(0x02);
    let replay_other_tx = unique_connector_spending_tx(0x03);

    for variant in all_state_variants() {
        let expected = expected_outcomes(&variant);

        // Scenario 1: fresh spend.
        let observed_fresh = outcome_of(&variant, run(variant.clone(), fresh_tx.clone()));
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
            let observed = outcome_of(&state, run(state.clone(), fresh_with_stake_tx.clone()));
            assert_eq!(
                observed, expected,
                "with-stake-pre-set outcome mismatch in state {variant}"
            );
        }

        // Scenario 3a: same-txid replay (matches the recorded connector spend).
        if let Some(expected_same) = expected.replay_same_txid.clone() {
            let (state, replay_tx) = prepare_replay(variant.clone());
            let observed = outcome_of(&state, run(state.clone(), replay_tx));
            assert_eq!(
                observed, expected_same,
                "replay (same txid) outcome mismatch in state {variant}"
            );
        }

        // Scenario 3b: a different txid arrives at a state that already
        // has a connector spend recorded.
        if let Some(expected_other) = expected.replay_other_txid.clone() {
            let (state, _) = prepare_replay(variant.clone());
            let observed = outcome_of(&state, run(state.clone(), replay_other_tx.clone()));
            assert_eq!(
                observed, expected_other,
                "replay (different txid) outcome mismatch in state {variant}"
            );
        }
    }
}

/// A misrouted legitimate payout transaction (uncontested or contested)
/// would otherwise satisfy the connector-outpoint check, since the payout
/// is what consumes the connector under normal flow. The STF rejects it
/// in every state where `is_payout_tx` recognises a payout, so a benign
/// payout can never regress into connector-spend abort logic.
#[test]
fn rejects_legitimate_payout_tx_misrouted_as_connector_spend() {
    // A connector-spending tx whose txid we will splice into each state's
    // legitimate-payout slot in turn.
    let payout_tx = canonical_connector_spending_tx();
    let payout_txid = payout_tx.compute_txid();

    // One case per branch of `is_payout_tx` in transitions/payout.rs.
    let cases: Vec<(&str, GraphState)> = vec![
        ("Claimed.uncontested_payout", {
            let mut state = claimed_state(100, Txid::all_zeros(), vec![]);
            if let GraphState::Claimed { graph_summary, .. } = &mut state {
                graph_summary.uncontested_payout = payout_txid;
            }
            state
        }),
        ("Claimed.contested_payout", {
            let mut state = claimed_state(100, Txid::all_zeros(), vec![]);
            if let GraphState::Claimed { graph_summary, .. } = &mut state {
                graph_summary.contested_payout = payout_txid;
            }
            state
        }),
        ("Contested.contested_payout", {
            let mut state = contested_state();
            if let GraphState::Contested { graph_summary, .. } = &mut state {
                graph_summary.contested_payout = payout_txid;
            }
            state
        }),
        ("BridgeProofPosted.contested_payout", {
            let mut state = bridge_proof_posted_state();
            if let GraphState::BridgeProofPosted { graph_summary, .. } = &mut state {
                graph_summary.contested_payout = payout_txid;
            }
            state
        }),
        ("CounterProofPosted.contested_payout", {
            let mut state = counter_proof_posted_state();
            if let GraphState::CounterProofPosted { graph_summary, .. } = &mut state {
                graph_summary.contested_payout = payout_txid;
            }
            state
        }),
        ("AllNackd.expected_payout_txid", {
            let mut state = all_nackd_state();
            if let GraphState::AllNackd {
                expected_payout_txid,
                ..
            } = &mut state
            {
                *expected_payout_txid = payout_txid;
            }
            state
        }),
    ];

    for (case_name, state) in cases {
        let observed = outcome_of(&state, run(state.clone(), payout_tx.clone()));
        assert_eq!(
            observed,
            Outcome::Rejected,
            "expected Rejected for misrouted payout tx in case {case_name}"
        );
    }
}

/// A misrouted/injected event whose tx does not actually consume the
/// payout-connector outpoint must be rejected — it cannot record
/// `payout_connector_spent`, abort the graph, or alter terminal states.
/// Pre-`Claimed` states, where no connector exists, fall through to the
/// regular `InvalidEvent` path because the defensive guard does not apply
/// to them.
#[test]
fn rejects_event_whose_tx_does_not_spend_connector_outpoint() {
    let unrelated_tx = generate_spending_tx(test_deposit_outpoint(), &[]);

    for variant in all_state_variants() {
        let observed = outcome_of(&variant, run(variant.clone(), unrelated_tx.clone()));
        let claim_txid_known = matches!(
            variant,
            GraphState::Claimed { .. }
                | GraphState::Contested { .. }
                | GraphState::BridgeProofPosted { .. }
                | GraphState::CounterProofPosted { .. }
                | GraphState::BridgeProofTimedout { .. }
                | GraphState::Acked { .. }
                | GraphState::AllNackd { .. }
        );
        let expected = if claim_txid_known {
            // Defensive guard fires: tx doesn't spend the connector for this
            // state's claim → Rejected.
            Outcome::Rejected
        } else if matches!(
            variant,
            GraphState::Withdrawn { .. } | GraphState::Slashed { .. } | GraphState::Aborted { .. }
        ) {
            // Terminal states reject all events regardless of tx shape.
            Outcome::Rejected
        } else {
            // Pre-`Claimed`: no connector outpoint exists, so the guard does
            // not apply and the regular protocol-breach path returns
            // `InvalidEvent`.
            Outcome::InvalidEvent
        };
        assert_eq!(
            observed, expected,
            "non-connector-spending tx outcome mismatch in state {variant}"
        );
    }
}
