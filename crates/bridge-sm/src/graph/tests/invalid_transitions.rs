//! Unit tests asserting every GSM state transition rejects invalid source
//! states.
//!
//! Coverage strategy: for each state-advancing transition, iterate every
//! [`GraphState`] variant returned by [`all_state_variants`], skip the
//! transition's valid source states, and assert the event is rejected from the
//! rest without mutating them. Leaning on that one enumeration helper keeps the
//! coverage exhaustive as new variants are added.
//!
//! Cross-cutting handlers (`NewBlock`, `StakeSpent`, `PayoutConnectorSpent`,
//! the `DepositMessage` family, ...) carry their own idempotency/abort
//! semantics, have dedicated tests, and are out of scope here.

use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_test_utils::prelude::generate_txid;

use super::{
    ASSIGNMENT_DEADLINE, CLAIM_BLOCK_HEIGHT, FULFILLMENT_BLOCK_HEIGHT, LATER_BLOCK_HEIGHT,
    TEST_DEPOSIT_IDX, TEST_NONPOV_IDX, TEST_POV_IDX, create_sm, dummy_proof_receipt,
    mock_states::{TEST_GRAPH_SUMMARY, all_state_variants},
    test_bridge_proof_tx, test_counterproof_nack_tx, test_counterproof_tx, test_deposit_params,
    test_graph_sm_cfg, test_recipient_desc,
};
use crate::{
    graph::{
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

/// One state-advancing transition: display name, the predicate selecting the
/// source states it legitimately accepts (mirroring the accepting match arms in
/// `graph::transitions`), and a builder for a well-formed event.
type TransitionCase = (&'static str, fn(&GraphState) -> bool, fn() -> GraphEvent);

// ===== Event builders =====
//
// Each builder produces a well-formed event with a valid operator index and
// the canonical test txids, so that rejection is driven purely by the source
// *state* rather than by malformed event content.

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
        pubnonces: Vec::new(),
    }
    .into()
}

fn partials_received_event() -> GraphEvent {
    GraphPartialsReceivedEvent {
        operator_idx: TEST_NONPOV_IDX,
        partial_signatures: Vec::new(),
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
        payout_txid: TEST_GRAPH_SUMMARY.uncontested_payout,
    }
    .into()
}

// ===== Exhaustive per-transition rejection =====

#[test]
fn every_transition_rejects_its_invalid_source_states() {
    #[rustfmt::skip]
    let cases: [TransitionCase; 14] = [
        ("GraphDataProduced",           |s| matches!(s, GraphState::Created { .. }),                                                                                                                        graph_data_produced_event),
        ("AdaptorsVerified",            |s| matches!(s, GraphState::GraphGenerated { .. }),                                                                                                                 adaptors_verified_event),
        ("NoncesReceived",              |s| matches!(s, GraphState::AdaptorsVerified { .. }),                                                                                                               nonces_received_event),
        ("PartialsReceived",            |s| matches!(s, GraphState::NoncesCollected { .. }),                                                                                                                partials_received_event),
        ("WithdrawalAssigned",          |s| matches!(s, GraphState::GraphSigned { .. } | GraphState::Assigned { .. }),                                                                                      withdrawal_assigned_event),
        ("FulfillmentConfirmed",        |s| matches!(s, GraphState::Assigned { .. }),                                                                                                                       fulfillment_confirmed_event),
        ("ClaimConfirmed",              |s| matches!(s, GraphState::GraphSigned { .. } | GraphState::Assigned { .. } | GraphState::Fulfilled { .. }),                                                        claim_confirmed_event),
        ("ContestConfirmed",            |s| matches!(s, GraphState::Claimed { .. }),                                                                                                                        contest_confirmed_event),
        ("BridgeProofConfirmed",        |s| matches!(s, GraphState::Contested { .. } | GraphState::CounterProofPosted { refuted_bridge_proof: None, .. }),                                                  bridge_proof_confirmed_event),
        ("BridgeProofTimeoutConfirmed", |s| matches!(s, GraphState::Contested { .. } | GraphState::CounterProofPosted { refuted_bridge_proof: None, .. }),                                                  bridge_proof_timeout_confirmed_event),
        ("CounterProofConfirmed",       |s| matches!(s, GraphState::Contested { .. } | GraphState::BridgeProofPosted { .. } | GraphState::CounterProofPosted { .. }),                                        counterproof_confirmed_event),
        ("CounterProofAckConfirmed",    |s| matches!(s, GraphState::CounterProofPosted { .. }),                                                                                                             counterproof_ack_confirmed_event),
        ("CounterProofNackConfirmed",   |s| matches!(s, GraphState::CounterProofPosted { .. }),                                                                                                             counterproof_nack_confirmed_event),
        ("PayoutConfirmed",             |s| matches!(s, GraphState::Claimed { .. } | GraphState::Contested { .. } | GraphState::BridgeProofPosted { .. } | GraphState::CounterProofPosted { .. } | GraphState::AllNackd { .. }), payout_confirmed_event),
    ];

    let cfg = test_graph_sm_cfg();

    for (transition, is_valid_source, make_event) in cases {
        let (mut skipped, mut rejected) = (0usize, 0usize);

        for state in all_state_variants() {
            if is_valid_source(&state) {
                skipped += 1;
                continue;
            }

            let state_name = state.to_string();
            let mut sm = create_sm(state.clone());
            let result = sm.process_event(cfg.clone(), make_event());

            assert!(
                result.is_err(),
                "{transition}: expected rejection from invalid source state {state_name}, got {result:?}",
            );
            assert_eq!(
                sm.state(),
                &state,
                "{transition}: a rejected event must leave source state {state_name} unchanged",
            );
            rejected += 1;
        }

        // A predicate that matched nothing (or everything) would silently gut a
        // transition's coverage; require both buckets to be non-empty.
        assert!(
            skipped > 0,
            "{transition}: predicate matched no valid source state"
        );
        assert!(
            rejected > 0,
            "{transition}: no invalid source states exercised"
        );
    }
}
