//! Asserts the error kind each GSM transition returns from every source state it does not
//! advance from, and that the state is left untouched.
//!
//! The kind matters: the orchestrator treats `InvalidEvent` as fatal, while `Duplicate` and
//! `Rejected` are survivable. Cross-cutting handlers (`NewBlock`, `StakeSpent`, ...) have
//! their own tests.

use std::sync::{Arc, LazyLock};

use musig2::PartialSignature;
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_test_utils::prelude::generate_txid;
use strata_bridge_tx_graph::game_graph::{DepositParams, GameGraphSummary};

use super::{
    ASSIGNMENT_DEADLINE, CLAIM_BLOCK_HEIGHT, FULFILLMENT_BLOCK_HEIGHT, INITIAL_BLOCK_HEIGHT,
    LATER_BLOCK_HEIGHT, TEST_DEPOSIT_IDX, TEST_NONPOV_IDX, TEST_POV_IDX, create_sm,
    dummy_proof_receipt,
    mock_states::{
        TEST_GRAPH_SUMMARY, adaptors_verified_state, all_state_variants, nonces_collected_state,
        test_nonce_context_with,
    },
    test_bridge_proof_tx, test_counterproof_nack_tx, test_counterproof_tx, test_deposit_params,
    test_graph_sm_cfg, test_recipient_desc,
    utils::{NonceContext, build_partial_signatures},
};
use crate::{
    graph::{
        config::GraphSMCfg,
        errors::GSMError,
        events::{
            AdaptorsVerifiedEvent, BridgeProofConfirmedEvent, BridgeProofTimeoutConfirmedEvent,
            ClaimConfirmedEvent, ContestConfirmedEvent, CounterProofAckConfirmedEvent,
            CounterProofConfirmedEvent, CounterProofNackConfirmedEvent, FulfillmentConfirmedEvent,
            GraphDataGeneratedEvent, GraphEvent, GraphNoncesReceivedEvent,
            GraphPartialsReceivedEvent, PayoutConfirmedEvent, WithdrawalAssignedEvent,
        },
        state::GraphState,
    },
    state_machine::StateMachine,
};

/// The arm of a transition's handler that a source state lands in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arm {
    /// Covered by the handler's own tests, so skipped here.
    Accepts,
    Duplicate,
    Invalid,
    Rejected,
}

impl From<&GSMError> for Arm {
    fn from(err: &GSMError) -> Self {
        match err {
            GSMError::Duplicate { .. } => Arm::Duplicate,
            GSMError::InvalidEvent { .. } => Arm::Invalid,
            GSMError::Rejected { .. } => Arm::Rejected,
        }
    }
}

/// Mirrors the `match` of one handler in `graph::transitions`.
struct TransitionCase {
    transition: &'static str,
    event: fn() -> GraphEvent,
    arm: fn(&GraphState) -> Arm,
}

// Peer-driven events have `InvalidEvent` softened to `Rejected`, the same kind payload
// validation yields, so only a payload the accepting arm takes attributes a rejection to the
// state. The partials only verify under the config their graph was built with.
struct SigningFixtures {
    cfg: Arc<GraphSMCfg>,
    deposit_params: DepositParams,
    graph_summary: GameGraphSummary,
    nonce_ctx: NonceContext,
    partial_sigs: Vec<PartialSignature>,
}

static SIGNING_FIXTURES: LazyLock<SigningFixtures> = LazyLock::new(|| {
    let cfg = test_graph_sm_cfg();
    let (deposit_params, graph_summary, nonce_ctx) = test_nonce_context_with(&cfg);
    let partial_sigs = build_partial_signatures(
        &nonce_ctx.signers,
        &nonce_ctx.key_agg_ctxs,
        &nonce_ctx.agg_nonces,
        &nonce_ctx.signing_infos,
        0,
    )[&TEST_NONPOV_IDX]
        .clone();
    SigningFixtures {
        cfg,
        deposit_params,
        graph_summary,
        nonce_ctx,
        partial_sigs,
    }
});

fn graph_data_produced_event() -> GraphEvent {
    let params = test_deposit_params();
    GraphDataGeneratedEvent {
        graph_idx: GraphIdx {
            deposit: TEST_DEPOSIT_IDX,
            operator: TEST_POV_IDX,
        },
        claim_funds: bitcoin::OutPoint::default(),
        adaptor_pubkeys: params.adaptor_pubkeys,
        fault_pubkeys: params.fault_pubkeys,
    }
    .into()
}

fn adaptors_verified_event() -> GraphEvent {
    AdaptorsVerifiedEvent {}.into()
}

fn nonces_received_event() -> GraphEvent {
    GraphNoncesReceivedEvent {
        operator_idx: TEST_NONPOV_IDX,
        pubnonces: SIGNING_FIXTURES.nonce_ctx.pubnonces[&TEST_NONPOV_IDX].clone(),
    }
    .into()
}

fn partials_received_event() -> GraphEvent {
    GraphPartialsReceivedEvent {
        operator_idx: TEST_NONPOV_IDX,
        partial_signatures: SIGNING_FIXTURES.partial_sigs.clone(),
    }
    .into()
}

fn withdrawal_assigned_event() -> GraphEvent {
    WithdrawalAssignedEvent {
        assignee: TEST_POV_IDX,
        deadline: ASSIGNMENT_DEADLINE,
        recipient_desc: test_recipient_desc(1),
    }
    .into()
}

fn fulfillment_confirmed_event() -> GraphEvent {
    FulfillmentConfirmedEvent {
        fulfillment_txid: generate_txid(),
        fulfillment_block_height: FULFILLMENT_BLOCK_HEIGHT,
    }
    .into()
}

fn claim_confirmed_event() -> GraphEvent {
    ClaimConfirmedEvent {
        claim_txid: TEST_GRAPH_SUMMARY.claim,
        claim_block_height: CLAIM_BLOCK_HEIGHT,
    }
    .into()
}

fn contest_confirmed_event() -> GraphEvent {
    ContestConfirmedEvent {
        contest_txid: TEST_GRAPH_SUMMARY.contest,
        contest_block_height: LATER_BLOCK_HEIGHT,
    }
    .into()
}

fn bridge_proof_confirmed_event() -> GraphEvent {
    BridgeProofConfirmedEvent {
        bridge_proof_block_height: LATER_BLOCK_HEIGHT,
        tx: test_bridge_proof_tx(),
        proof: dummy_proof_receipt(),
    }
    .into()
}

fn bridge_proof_timeout_confirmed_event() -> GraphEvent {
    BridgeProofTimeoutConfirmedEvent {
        bridge_proof_timeout_txid: TEST_GRAPH_SUMMARY.bridge_proof_timeout,
        bridge_proof_timeout_block_height: LATER_BLOCK_HEIGHT,
    }
    .into()
}

fn counterproof_confirmed_event() -> GraphEvent {
    CounterProofConfirmedEvent {
        counterproof_block_height: LATER_BLOCK_HEIGHT,
        tx: test_counterproof_tx(),
        counterprover_idx: TEST_NONPOV_IDX,
    }
    .into()
}

fn counterproof_ack_confirmed_event() -> GraphEvent {
    CounterProofAckConfirmedEvent {
        counterproof_ack_txid: TEST_GRAPH_SUMMARY.counterproofs[0].counterproof_ack,
        counterproof_ack_block_height: LATER_BLOCK_HEIGHT,
        counterprover_idx: TEST_NONPOV_IDX,
    }
    .into()
}

fn counterproof_nack_confirmed_event() -> GraphEvent {
    CounterProofNackConfirmedEvent {
        tx: test_counterproof_nack_tx(),
        counterprover_idx: TEST_NONPOV_IDX,
    }
    .into()
}

fn payout_confirmed_event() -> GraphEvent {
    PayoutConfirmedEvent {
        payout_txid: TEST_GRAPH_SUMMARY.contested_payout,
    }
    .into()
}

// Arms as seen by `create_sm` (the POV's own graph); graph data and adaptor verification
// place their `Duplicate` arm elsewhere for a non-POV graph.
const CASES: [TransitionCase; 14] = [
    TransitionCase {
        transition: "GraphDataProduced",
        event: graph_data_produced_event,
        arm: |state| match state {
            GraphState::Created { .. } => Arm::Accepts,
            GraphState::AdaptorsVerified { .. } => Arm::Duplicate,
            _ => Arm::Rejected,
        },
    },
    TransitionCase {
        transition: "AdaptorsVerified",
        event: adaptors_verified_event,
        // Unordered external service, so a late delivery is tolerated.
        arm: |state| match state {
            GraphState::GraphGenerated { .. } => Arm::Accepts,
            _ => Arm::Rejected,
        },
    },
    TransitionCase {
        transition: "NoncesReceived",
        event: nonces_received_event,
        arm: |state| match state {
            GraphState::AdaptorsVerified { .. } => Arm::Accepts,
            GraphState::NoncesCollected { .. } => Arm::Duplicate,
            _ => Arm::Rejected,
        },
    },
    TransitionCase {
        transition: "PartialsReceived",
        event: partials_received_event,
        arm: |state| match state {
            GraphState::NoncesCollected { .. } => Arm::Accepts,
            GraphState::GraphSigned { .. } => Arm::Duplicate,
            _ => Arm::Rejected,
        },
    },
    TransitionCase {
        transition: "WithdrawalAssigned",
        event: withdrawal_assigned_event,
        // Re-delivered by the ASM client.
        arm: |state| match state {
            GraphState::GraphSigned { .. } | GraphState::Assigned { .. } => Arm::Accepts,
            GraphState::Created { .. }
            | GraphState::GraphGenerated { .. }
            | GraphState::AdaptorsVerified { .. }
            | GraphState::NoncesCollected { .. } => Arm::Invalid,
            _ => Arm::Duplicate,
        },
    },
    TransitionCase {
        transition: "FulfillmentConfirmed",
        event: fulfillment_confirmed_event,
        arm: |state| match state {
            GraphState::Assigned { .. } => Arm::Accepts,
            GraphState::Fulfilled { .. } => Arm::Duplicate,
            _ => Arm::Invalid,
        },
    },
    TransitionCase {
        transition: "ClaimConfirmed",
        event: claim_confirmed_event,
        arm: |state| match state {
            GraphState::GraphSigned { .. }
            | GraphState::Assigned { .. }
            | GraphState::Fulfilled { .. } => Arm::Accepts,
            GraphState::Claimed { .. } => Arm::Duplicate,
            // Nothing to contest with yet, but must not crash the node.
            GraphState::GraphGenerated { .. }
            | GraphState::AdaptorsVerified { .. }
            | GraphState::NoncesCollected { .. } => Arm::Rejected,
            _ => Arm::Invalid,
        },
    },
    TransitionCase {
        transition: "ContestConfirmed",
        event: contest_confirmed_event,
        arm: |state| match state {
            GraphState::Claimed { .. } => Arm::Accepts,
            GraphState::Contested { .. } => Arm::Duplicate,
            _ => Arm::Invalid,
        },
    },
    TransitionCase {
        transition: "BridgeProofConfirmed",
        event: bridge_proof_confirmed_event,
        arm: |state| match state {
            GraphState::Contested { .. }
            | GraphState::CounterProofPosted {
                refuted_bridge_proof: None,
                ..
            } => Arm::Accepts,
            GraphState::BridgeProofPosted { .. }
            | GraphState::CounterProofPosted {
                refuted_bridge_proof: Some(_),
                ..
            } => Arm::Duplicate,
            _ => Arm::Invalid,
        },
    },
    TransitionCase {
        transition: "BridgeProofTimeoutConfirmed",
        event: bridge_proof_timeout_confirmed_event,
        // Shares a connector with the bridge proof, so after a proof it is invalid.
        arm: |state| match state {
            GraphState::Contested { .. }
            | GraphState::CounterProofPosted {
                refuted_bridge_proof: None,
                ..
            } => Arm::Accepts,
            GraphState::BridgeProofTimedout { .. } => Arm::Duplicate,
            _ => Arm::Invalid,
        },
    },
    TransitionCase {
        transition: "CounterProofConfirmed",
        event: counterproof_confirmed_event,
        arm: |state| match state {
            GraphState::Contested { .. }
            | GraphState::BridgeProofPosted { .. }
            | GraphState::CounterProofPosted { .. } => Arm::Accepts,
            _ => Arm::Invalid,
        },
    },
    TransitionCase {
        transition: "CounterProofAckConfirmed",
        event: counterproof_ack_confirmed_event,
        arm: |state| match state {
            GraphState::CounterProofPosted { .. } => Arm::Accepts,
            GraphState::Acked { .. } => Arm::Duplicate,
            _ => Arm::Invalid,
        },
    },
    TransitionCase {
        transition: "CounterProofNackConfirmed",
        event: counterproof_nack_confirmed_event,
        arm: |state| match state {
            GraphState::CounterProofPosted { .. } => Arm::Accepts,
            GraphState::AllNackd { .. } => Arm::Duplicate,
            _ => Arm::Invalid,
        },
    },
    TransitionCase {
        transition: "PayoutConfirmed",
        event: payout_confirmed_event,
        arm: |state| match state {
            GraphState::Claimed { .. }
            | GraphState::Contested { .. }
            | GraphState::BridgeProofPosted { .. }
            | GraphState::CounterProofPosted { .. }
            | GraphState::AllNackd { .. } => Arm::Accepts,
            GraphState::Withdrawn { .. } => Arm::Duplicate,
            _ => Arm::Invalid,
        },
    },
];

#[test]
fn every_transition_rejects_its_non_accepting_source_states() {
    let cfg = &SIGNING_FIXTURES.cfg;

    for case in CASES {
        let transition = case.transition;
        let (mut accepting, mut rejected) = (0usize, 0usize);

        for state in all_state_variants() {
            let expected = (case.arm)(&state);
            if expected == Arm::Accepts {
                accepting += 1;
                continue;
            }

            let mut sm = create_sm(state.clone());
            let result = sm.process_event(cfg.clone(), (case.event)());

            match &result {
                Ok(_) => panic!("{transition}: accepted from {state}, expected {expected:?}"),
                Err(err) => assert_eq!(
                    Arm::from(err),
                    expected,
                    "{transition}: wrong error kind from {state}: {err:?}",
                ),
            }
            assert_eq!(
                sm.state(),
                &state,
                "{transition}: a rejected event must leave {state} unchanged",
            );
            rejected += 1;
        }

        // A mis-specified arm would otherwise silently gut the coverage.
        assert!(accepting > 0, "{transition}: no accepting source state");
        assert!(rejected > 0, "{transition}: no source state exercised");
    }
}

#[test]
fn peer_driven_events_are_accepted_from_their_source_state() {
    let SigningFixtures {
        cfg,
        deposit_params,
        graph_summary,
        nonce_ctx,
        ..
    } = &*SIGNING_FIXTURES;
    let cases = [
        (
            GraphState::new(INITIAL_BLOCK_HEIGHT),
            graph_data_produced_event(),
        ),
        (
            adaptors_verified_state(deposit_params.clone(), graph_summary.clone()),
            nonces_received_event(),
        ),
        (
            nonces_collected_state(nonce_ctx, deposit_params.clone(), graph_summary.clone()),
            partials_received_event(),
        ),
    ];

    for (state, event) in cases {
        let mut sm = create_sm(state.clone());
        let result = sm.process_event(cfg.clone(), event.clone());
        assert!(
            result.is_ok(),
            "{event} must be accepted from {state}, got {result:?}"
        );
    }
}
