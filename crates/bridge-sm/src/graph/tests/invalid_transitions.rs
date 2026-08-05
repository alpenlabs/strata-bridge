//! Unit tests asserting how every GSM state transition treats the source
//! states it does not advance from.
//!
//! Coverage strategy: each state-advancing transition declares, per source
//! state, which arm of its handler that state lands in. The test then iterates
//! every [`GraphState`] variant returned by [`all_state_variants`] and asserts
//! that each non-accepting state yields exactly the declared error kind without
//! mutating the state. Leaning on that one enumeration helper keeps the
//! coverage exhaustive as new variants are added.
//!
//! The kinds are load-bearing at runtime: the orchestrator escalates
//! `InvalidEvent` to a fatal invariant violation, while `Duplicate` and
//! `Rejected` are survivable. Events are driven through `process_event` so the
//! kinds asserted are the ones the orchestrator sees, including the softening of
//! `InvalidEvent` to `Rejected` for peer-driven events.
//!
//! Cross-cutting handlers (`NewBlock`, `StakeSpent`, `PayoutConnectorSpent`,
//! the `DepositMessage` family, ...) carry their own idempotency/abort
//! semantics, have dedicated tests, and are out of scope here.

use std::sync::{Arc, LazyLock};

use musig2::{PartialSignature, PubNonce};
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_test_utils::prelude::generate_txid;
use strata_bridge_tx_graph::game_graph::{DepositParams, GameGraphSummary};

use super::{
    ASSIGNMENT_DEADLINE, CLAIM_BLOCK_HEIGHT, FULFILLMENT_BLOCK_HEIGHT, INITIAL_BLOCK_HEIGHT,
    LATER_BLOCK_HEIGHT, TEST_DEPOSIT_IDX, TEST_NONPOV_IDX, TEST_POV_IDX, create_sm,
    dummy_proof_receipt,
    mock_states::{
        TEST_GRAPH_SUMMARY, adaptors_verified_state, all_state_variants, nonces_collected_state,
    },
    test_bridge_proof_tx, test_counterproof_nack_tx, test_counterproof_tx, test_deposit_params,
    test_graph_data, test_graph_sm_cfg, test_recipient_desc,
    utils::{NonceContext, build_nonce_context, build_partial_signatures},
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
    /// An accepting arm. The outcome depends on the payload, which the
    /// handler's own tests cover, so these states are skipped here.
    Accepts,
    /// The state already reflects the event.
    Duplicate,
    /// The event is an invariant violation in this state.
    Invalid,
    /// The event is inapplicable in this state, but tolerated.
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

/// One state-advancing transition: a builder for its event, and the arm each
/// source state lands in, mirroring the `match` in `graph::transitions`.
struct TransitionCase {
    transition: &'static str,
    event: fn() -> GraphEvent,
    arm: fn(&GraphState) -> Arm,
}

// ===== Event builders =====
//
// Each builder produces a well-formed event, so that rejection is driven by the
// source *state* rather than by malformed event content.

/// Signing fixtures, along with the config their graph was generated under.
///
/// `test_graph_sm_cfg` draws fresh keys on every call and the sighashes depend
/// on them, so the partial signatures only verify under this same config.
struct SigningFixtures {
    cfg: Arc<GraphSMCfg>,
    deposit_params: DepositParams,
    graph_summary: GameGraphSummary,
    nonce_ctx: NonceContext,
}

/// Peer-driven events have `InvalidEvent` softened to `Rejected`, the same kind
/// payload validation yields, so the error kind cannot attribute a rejection to
/// the source state. Only a payload the accepting arm would take can: with it,
/// a handler that starts accepting an extra state returns `Ok` there.
static SIGNING_FIXTURES: LazyLock<SigningFixtures> = LazyLock::new(|| {
    let cfg = test_graph_sm_cfg();
    let (deposit_params, graph) = test_graph_data(&cfg);
    SigningFixtures {
        cfg,
        deposit_params,
        graph_summary: graph.summarize(),
        nonce_ctx: build_nonce_context(graph.musig_signing_info().pack()),
    }
});

static VALID_PUBNONCES: LazyLock<Vec<PubNonce>> =
    LazyLock::new(|| SIGNING_FIXTURES.nonce_ctx.pubnonces[&TEST_NONPOV_IDX].clone());

static VALID_PARTIAL_SIGS: LazyLock<Vec<PartialSignature>> = LazyLock::new(|| {
    let nonce_ctx = &SIGNING_FIXTURES.nonce_ctx;
    build_partial_signatures(
        &nonce_ctx.signers,
        &nonce_ctx.key_agg_ctxs,
        &nonce_ctx.agg_nonces,
        &nonce_ctx.signing_infos,
        0,
    )[&TEST_NONPOV_IDX]
        .clone()
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
        pubnonces: VALID_PUBNONCES.clone(),
    }
    .into()
}

fn partials_received_event() -> GraphEvent {
    GraphPartialsReceivedEvent {
        operator_idx: TEST_NONPOV_IDX,
        partial_signatures: VALID_PARTIAL_SIGS.clone(),
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

// ===== Exhaustive per-transition rejection =====

/// The arms below are those seen by `create_sm`, i.e. the POV operator's own
/// graph. `process_graph_data` and `process_adaptors_verification` place their
/// `Duplicate` arm on a different state for a non-POV graph.
const CASES: [TransitionCase; 14] = [
    TransitionCase {
        transition: "GraphDataProduced",
        event: graph_data_produced_event,
        // Peer-driven, so a stale delivery must never be fatal.
        arm: |state| match state {
            GraphState::Created { .. } => Arm::Accepts,
            GraphState::AdaptorsVerified { .. } => Arm::Duplicate,
            _ => Arm::Rejected,
        },
    },
    TransitionCase {
        transition: "AdaptorsVerified",
        event: adaptors_verified_event,
        // Emitted by an external service with no ordering guarantee, so a late
        // delivery is tolerated rather than treated as an invariant violation.
        arm: |state| match state {
            GraphState::GraphGenerated { .. } => Arm::Accepts,
            _ => Arm::Rejected,
        },
    },
    TransitionCase {
        transition: "NoncesReceived",
        event: nonces_received_event,
        // Peer-driven, so a stale delivery must never be fatal.
        arm: |state| match state {
            GraphState::AdaptorsVerified { .. } => Arm::Accepts,
            GraphState::NoncesCollected { .. } => Arm::Duplicate,
            _ => Arm::Rejected,
        },
    },
    TransitionCase {
        transition: "PartialsReceived",
        event: partials_received_event,
        // Peer-driven, so a stale delivery must never be fatal.
        arm: |state| match state {
            GraphState::NoncesCollected { .. } => Arm::Accepts,
            GraphState::GraphSigned { .. } => Arm::Duplicate,
            _ => Arm::Rejected,
        },
    },
    TransitionCase {
        transition: "WithdrawalAssigned",
        event: withdrawal_assigned_event,
        // Re-delivered by the ASM client, so every state past assignment
        // already reflects it.
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
        // The timeout and the bridge proof spend the same connector, so a
        // timeout after a posted proof is invalid rather than a duplicate.
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

        // An arm that matched nothing (or everything) would silently gut a
        // transition's coverage; require both buckets to be non-empty.
        assert!(accepting > 0, "{transition}: no accepting source state");
        assert!(rejected > 0, "{transition}: no source state exercised");
    }
}

/// Backs the peer-driven rows above: their payloads are ones an accepting arm
/// takes, so a rejection from any other state is down to the state.
#[test]
fn peer_driven_events_are_accepted_from_their_source_state() {
    let SigningFixtures {
        cfg,
        deposit_params,
        graph_summary,
        nonce_ctx,
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
