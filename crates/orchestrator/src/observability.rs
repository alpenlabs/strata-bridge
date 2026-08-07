//! Stable metric names, bounded labels, and observability-specific type classification.
//!
//! Object identifiers and raw errors deliberately do not appear in this module's metric labels.
//! They belong in spans and structured logs, where they do not create unbounded Prometheus series.

use std::time::Duration;

use metrics::{Unit, counter, describe_counter, describe_histogram, histogram};

use crate::{
    errors::{PipelineError, ProcessError},
    events_mux::UnifiedEvent,
    persister::PersistError,
};

const PIPELINE_EVENT_DURATION_SECONDS: &str = "strata_bridge_pipeline_event_duration_seconds";
const PIPELINE_ROUTING_TOTAL: &str = "strata_bridge_pipeline_routing_total";
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
}
