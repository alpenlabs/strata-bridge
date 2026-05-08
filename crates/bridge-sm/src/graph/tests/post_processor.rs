//! Unit tests for GraphSM post-STF duty derivation.
//!
//! Coverage strategy: a single table-driven test iterates every [`GraphState`]
//! variant returned by [`all_state_variants`] and asserts post-processor output
//! against a per-state [`expected_outcomes`] mapping function. The mapping uses
//! an exhaustive `match` over [`GraphState`], so adding a new variant is a
//! compile error until the post-processing behavior is classified.

use bitcoin::{
    OutPoint,
    hashes::{Hash, sha256},
};
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_test_utils::prelude::generate_txid;
use strata_bridge_tx_graph::transactions::prelude::ClaimTx;

use crate::{
    cross_sm_context::CrossSmContext,
    graph::{
        duties::GraphDuty,
        state::GraphState,
        tests::{create_nonpov_sm, create_sm, mock_states::all_state_variants, test_graph_sm_cfg},
    },
    state_machine::StateMachine,
};

const UNSTAKING_PREIMAGE: [u8; 32] = [0x42; 32];

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Outcome {
    EmitsUnstakingBurn,
    NoDuties,
}

#[derive(Debug, Clone)]
struct StateClassification {
    /// Non-owner watchtower, matching preimage present in cross-SM context.
    matching_non_owner: Outcome,
    /// Graph owner, matching preimage present in cross-SM context.
    graph_owner: Outcome,
    /// Non-owner watchtower, no preimage present in cross-SM context.
    missing_preimage: Outcome,
    /// Non-owner watchtower, preimage present but mismatched against graph context.
    mismatched_preimage: Outcome,
    /// `Some(_)` if the state carries `payout_connector_spent`. The contained
    /// outcome describes what happens when that field is pre-set and a matching
    /// preimage arrives.
    with_connector_pre_set: Option<Outcome>,
}

/// Exhaustive over [`GraphState`] — adding a new variant is a compile error.
fn expected_outcomes(state: &GraphState) -> StateClassification {
    match state {
        // Pre-claim states have no claim payout connector to burn.
        GraphState::Created { .. }
        | GraphState::GraphGenerated { .. }
        | GraphState::AdaptorsVerified { .. }
        | GraphState::NoncesCollected { .. }
        | GraphState::GraphSigned { .. }
        | GraphState::Assigned { .. }
        | GraphState::Fulfilled { .. } => StateClassification {
            matching_non_owner: Outcome::NoDuties,
            graph_owner: Outcome::NoDuties,
            missing_preimage: Outcome::NoDuties,
            mismatched_preimage: Outcome::NoDuties,
            with_connector_pre_set: None,
        },

        // Post-claim two-fact states can burn the payout connector unless a
        // connector spend has already been recorded.
        GraphState::Claimed { .. }
        | GraphState::Contested { .. }
        | GraphState::BridgeProofPosted { .. }
        | GraphState::CounterProofPosted { .. } => StateClassification {
            matching_non_owner: Outcome::EmitsUnstakingBurn,
            graph_owner: Outcome::NoDuties,
            missing_preimage: Outcome::NoDuties,
            mismatched_preimage: Outcome::NoDuties,
            with_connector_pre_set: Some(Outcome::NoDuties),
        },

        // Slash-path states no longer carry the connector-spend fact, but the
        // payout connector still exists until a spend is observed on-chain.
        GraphState::BridgeProofTimedout { .. }
        | GraphState::Acked { .. }
        | GraphState::AllNackd { .. } => StateClassification {
            matching_non_owner: Outcome::EmitsUnstakingBurn,
            graph_owner: Outcome::NoDuties,
            missing_preimage: Outcome::NoDuties,
            mismatched_preimage: Outcome::NoDuties,
            with_connector_pre_set: None,
        },

        // Terminal states must not derive new duties.
        GraphState::Withdrawn { .. } | GraphState::Slashed { .. } | GraphState::Aborted { .. } => {
            StateClassification {
                matching_non_owner: Outcome::NoDuties,
                graph_owner: Outcome::NoDuties,
                missing_preimage: Outcome::NoDuties,
                mismatched_preimage: Outcome::NoDuties,
                with_connector_pre_set: None,
            }
        }
    }
}

#[test]
fn post_stf_hook_dispatch_table_for_unstaking_burn_is_exhaustive() {
    let matching_context = CrossSmContext::with_unstaking_preimage(UNSTAKING_PREIMAGE);
    let missing_context = CrossSmContext::default();

    // Every variant is exercised below. `all_state_variants()` returns one
    // representative per variant; if a new variant is added the
    // `expected_outcomes` match above fails to compile.
    for variant in all_state_variants() {
        let classification = expected_outcomes(&variant);

        let (graph_idx, duties) = run_non_owner(
            variant.clone(),
            matching_unstaking_image(),
            &matching_context,
        );
        let observed_matching = outcome_of(graph_idx, duties, &variant);
        assert_eq!(
            observed_matching, classification.matching_non_owner,
            "matching non-owner outcome mismatch in state {variant}"
        );

        let (graph_idx, duties) = run_owner(
            variant.clone(),
            matching_unstaking_image(),
            &matching_context,
        );
        let observed_owner = outcome_of(graph_idx, duties, &variant);
        assert_eq!(
            observed_owner, classification.graph_owner,
            "graph-owner outcome mismatch in state {variant}"
        );

        let (graph_idx, duties) = run_non_owner(
            variant.clone(),
            matching_unstaking_image(),
            &missing_context,
        );
        let observed_missing_preimage = outcome_of(graph_idx, duties, &variant);
        assert_eq!(
            observed_missing_preimage, classification.missing_preimage,
            "missing-preimage outcome mismatch in state {variant}"
        );

        let (graph_idx, duties) = run_non_owner(
            variant.clone(),
            mismatched_unstaking_image(),
            &matching_context,
        );
        let observed_mismatched_preimage = outcome_of(graph_idx, duties, &variant);
        assert_eq!(
            observed_mismatched_preimage, classification.mismatched_preimage,
            "mismatched-preimage outcome mismatch in state {variant}"
        );

        if let Some(expected) = classification.with_connector_pre_set {
            let mut state = variant.clone();
            assert!(
                state.set_payout_connector_spent(generate_txid()),
                "with_connector_pre_set is `Some` but state does not carry the field: {variant}"
            );

            let (graph_idx, duties) =
                run_non_owner(state, matching_unstaking_image(), &matching_context);
            let observed = outcome_of(graph_idx, duties, &variant);
            assert_eq!(
                observed, expected,
                "connector-pre-set outcome mismatch in state {variant}"
            );
        }
    }
}

fn run_non_owner(
    initial: GraphState,
    unstaking_image: sha256::Hash,
    cross_sm_context: &CrossSmContext,
) -> (GraphIdx, Vec<GraphDuty>) {
    let cfg = test_graph_sm_cfg();
    let mut sm = create_nonpov_sm(initial);
    sm.context.unstaking_image = unstaking_image;
    let graph_idx = sm.context.graph_idx();
    let duties = sm.run_post_stf_hook(&cfg, cross_sm_context);
    (graph_idx, duties)
}

fn run_owner(
    initial: GraphState,
    unstaking_image: sha256::Hash,
    cross_sm_context: &CrossSmContext,
) -> (GraphIdx, Vec<GraphDuty>) {
    let cfg = test_graph_sm_cfg();
    let mut sm = create_sm(initial);
    sm.context.unstaking_image = unstaking_image;
    let graph_idx = sm.context.graph_idx();
    let duties = sm.run_post_stf_hook(&cfg, cross_sm_context);
    (graph_idx, duties)
}

fn outcome_of(
    expected_graph_idx: GraphIdx,
    duties: Vec<GraphDuty>,
    initial: &GraphState,
) -> Outcome {
    if duties.is_empty() {
        return Outcome::NoDuties;
    }

    let [
        GraphDuty::PublishUnstakingBurn {
            graph_idx,
            unstaking_burn_tx,
            unstaking_preimage,
        },
    ] = duties.as_slice()
    else {
        panic!("unexpected post-STF duties: {duties:?}");
    };

    assert_eq!(*graph_idx, expected_graph_idx);
    assert_eq!(*unstaking_preimage, UNSTAKING_PREIMAGE);
    assert_eq!(
        unstaking_burn_tx.as_ref().input[0].previous_output,
        expected_burn_outpoint(initial),
        "unexpected burn outpoint in state {initial}"
    );
    Outcome::EmitsUnstakingBurn
}

fn expected_burn_outpoint(initial: &GraphState) -> OutPoint {
    let txid = match initial {
        GraphState::Claimed { graph_summary, .. }
        | GraphState::Contested { graph_summary, .. }
        | GraphState::BridgeProofPosted { graph_summary, .. }
        | GraphState::CounterProofPosted { graph_summary, .. } => graph_summary.claim,
        GraphState::BridgeProofTimedout { claim_txid, .. }
        | GraphState::Acked { claim_txid, .. }
        | GraphState::AllNackd { claim_txid, .. } => *claim_txid,
        other => panic!("state should not emit PublishUnstakingBurn: {other}"),
    };

    OutPoint {
        txid,
        vout: ClaimTx::PAYOUT_VOUT,
    }
}

fn matching_unstaking_image() -> sha256::Hash {
    sha256::Hash::hash(&UNSTAKING_PREIMAGE)
}

fn mismatched_unstaking_image() -> sha256::Hash {
    let mut image = matching_unstaking_image().to_byte_array();
    image[0] ^= 1;
    sha256::Hash::from_byte_array(image)
}
