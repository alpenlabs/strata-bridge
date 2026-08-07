//! Stable metric names, bounded labels, and observability-specific type classification.
//!
//! Object identifiers and raw errors deliberately do not appear in this module's metric labels.
//! They belong in spans and structured logs, where they do not create unbounded Prometheus series.

use std::time::Duration;

use metrics::{Unit, counter, describe_counter, describe_histogram, histogram};
use strata_bridge_sm::{
    deposit::state::DepositState, graph::state::GraphState, stake::state::StakeState,
};

use crate::{
    errors::{PipelineError, ProcessError},
    events_mux::UnifiedEvent,
    persister::PersistError,
    sm_types::SMId,
};

const PIPELINE_EVENT_DURATION_SECONDS: &str = "strata_bridge_pipeline_event_duration_seconds";
const PIPELINE_ROUTING_TOTAL: &str = "strata_bridge_pipeline_routing_total";
const SM_TRANSITIONS_TOTAL: &str = "strata_bridge_sm_transitions_total";
const SM_TRANSITION_DURATION_SECONDS: &str = "strata_bridge_sm_transition_duration_seconds";
const PERSISTENCE_DURATION_SECONDS: &str = "strata_bridge_persistence_duration_seconds";

pub(crate) fn describe_metrics() {
    describe_histogram!(
        PIPELINE_EVENT_DURATION_SECONDS,
        Unit::Seconds,
        "End-to-end time to classify, apply, persist, and dispatch one top-level event"
    );
    describe_counter!(
        PIPELINE_ROUTING_TOTAL,
        "Top-level off-chain event routing and classification outcomes"
    );
    describe_counter!(
        SM_TRANSITIONS_TOTAL,
        "State-machine event processing outcomes by bounded state-machine kind and state pair"
    );
    describe_histogram!(
        SM_TRANSITION_DURATION_SECONDS,
        Unit::Seconds,
        "State-machine event processing time"
    );
    describe_histogram!(
        PERSISTENCE_DURATION_SECONDS,
        Unit::Seconds,
        "Atomic state-machine persistence operation time"
    );
}

pub(crate) fn record_pipeline_event_finished(
    event_kind: &'static str,
    result: &'static str,
    error_class: &'static str,
    duration: Duration,
) {
    histogram!(
        PIPELINE_EVENT_DURATION_SECONDS,
        "event_kind" => event_kind,
        "result" => result,
        "error_class" => error_class
    )
    .record(duration.as_secs_f64());
}

pub(crate) fn record_routing(event_kind: &'static str, result: &'static str) {
    counter!(
        PIPELINE_ROUTING_TOTAL,
        "event_kind" => event_kind,
        "result" => result
    )
    .increment(1);
}

pub(crate) fn record_transition(
    sm_kind: &'static str,
    from_state: &'static str,
    to_state: &'static str,
    result: &'static str,
    duration: Duration,
) {
    counter!(
        SM_TRANSITIONS_TOTAL,
        "sm_kind" => sm_kind,
        "from_state" => from_state,
        "to_state" => to_state,
        "result" => result
    )
    .increment(1);
    // State pairs stay on the counter, where they describe lifecycle flow. They are omitted from
    // the duration distribution because they multiply series without improving latency triage.
    histogram!(
        SM_TRANSITION_DURATION_SECONDS,
        "sm_kind" => sm_kind,
        "result" => result
    )
    .record(duration.as_secs_f64());
}

pub(crate) fn record_persistence(
    result: &'static str,
    error_class: &'static str,
    duration: Duration,
) {
    histogram!(
        PERSISTENCE_DURATION_SECONDS,
        "result" => result,
        "error_class" => error_class
    )
    .record(duration.as_secs_f64());
}

pub(crate) const fn unified_event_kind(event: &UnifiedEvent) -> &'static str {
    match event {
        UnifiedEvent::OuroborosMessage(_) => "ouroboros_message",
        UnifiedEvent::Shutdown => "shutdown",
        UnifiedEvent::Block(_) => "block",
        UnifiedEvent::Assignment(_) => "assignment",
        UnifiedEvent::GossipMessage(_) => "gossip_message",
        UnifiedEvent::MosaicEvent(_) => "mosaic_event",
        UnifiedEvent::NagTick => "nag_tick",
        UnifiedEvent::RetryTick => "retry_tick",
        UnifiedEvent::SafeHarbour(_) => "safe_harbour",
    }
}

pub(crate) const fn sm_kind(id: &SMId) -> &'static str {
    match id {
        SMId::Deposit(_) => "deposit",
        SMId::Graph(_) => "graph",
        SMId::Stake(_) => "stake",
    }
}

pub(crate) const fn deposit_state_kind(state: &DepositState) -> &'static str {
    match state {
        DepositState::Created { .. } => "created",
        DepositState::GraphGenerated { .. } => "graph_generated",
        DepositState::DepositNoncesCollected { .. } => "deposit_nonces_collected",
        DepositState::DepositPartialsCollected { .. } => "deposit_partials_collected",
        DepositState::Deposited { .. } => "deposited",
        DepositState::Assigned { .. } => "assigned",
        DepositState::Fulfilled { .. } => "fulfilled",
        DepositState::PayoutDescriptorReceived { .. } => "payout_descriptor_received",
        DepositState::PayoutNoncesCollected { .. } => "payout_nonces_collected",
        DepositState::CooperativePathFailed { .. } => "cooperative_path_failed",
        DepositState::Spent { .. } => "spent",
        DepositState::Aborted => "aborted",
    }
}

pub(crate) const fn graph_state_kind(state: &GraphState) -> &'static str {
    match state {
        GraphState::Created { .. } => "created",
        GraphState::GraphGenerated { .. } => "graph_generated",
        GraphState::AdaptorsVerified { .. } => "adaptors_verified",
        GraphState::NoncesCollected { .. } => "nonces_collected",
        GraphState::GraphSigned { .. } => "graph_signed",
        GraphState::Assigned { .. } => "assigned",
        GraphState::Fulfilled { .. } => "fulfilled",
        GraphState::Claimed { .. } => "claimed",
        GraphState::Contested { .. } => "contested",
        GraphState::BridgeProofPosted { .. } => "bridge_proof_posted",
        GraphState::BridgeProofTimedout { .. } => "bridge_proof_timed_out",
        GraphState::CounterProofPosted { .. } => "counter_proof_posted",
        GraphState::AllNackd { .. } => "all_nacked",
        GraphState::Acked { .. } => "acked",
        GraphState::Withdrawn { .. } => "withdrawn",
        GraphState::Slashed { .. } => "slashed",
        GraphState::Aborted { .. } => "aborted",
    }
}

pub(crate) const fn stake_state_kind(state: &StakeState) -> &'static str {
    match state {
        StakeState::Created { .. } => "created",
        StakeState::StakeGraphGenerated { .. } => "stake_graph_generated",
        StakeState::UnstakingNoncesCollected { .. } => "unstaking_nonces_collected",
        StakeState::UnstakingSigned { .. } => "unstaking_signed",
        StakeState::Confirmed { .. } => "confirmed",
        StakeState::PreimageRevealed { .. } => "preimage_revealed",
        StakeState::Unstaked { .. } => "unstaked",
        StakeState::Slashed { .. } => "slashed",
    }
}

pub(crate) const fn pipeline_error_class(error: &PipelineError) -> &'static str {
    match error {
        PipelineError::Process(error) => process_error_class(error),
        PipelineError::Persist(error) => persist_error_class(error),
    }
}

const fn process_error_class(error: &ProcessError) -> &'static str {
    match error {
        ProcessError::SMNotFound(_) => "state_machine_not_found",
        ProcessError::InvalidInvocation(_, _) => "invalid_invocation",
        ProcessError::InvariantViolation(_, _, _, _) => "invariant_violation",
        ProcessError::RegistryInsert(_) => "registry_insertion",
    }
}

pub(crate) const fn persist_error_class(error: &PersistError) -> &'static str {
    match error {
        PersistError::DbErr(_) => "database",
        PersistError::RegistryInvariant(_) => "registry_invariant",
        PersistError::MissingStateMachine(_) => "state_machine_not_found",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periodic_event_kinds_are_stable_and_distinct() {
        assert_eq!(unified_event_kind(&UnifiedEvent::NagTick), "nag_tick");
        assert_eq!(unified_event_kind(&UnifiedEvent::RetryTick), "retry_tick");
    }

    #[test]
    fn state_machine_kinds_do_not_include_identifiers() {
        assert_eq!(sm_kind(&SMId::Deposit(42)), "deposit");
        assert_eq!(sm_kind(&SMId::Stake(7)), "stake");
    }
}
