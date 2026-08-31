//! Stable metric names, bounded labels, and observability-specific type classification.
//!
//! Object identifiers and raw errors deliberately do not appear in this module's metric labels.
//! They belong in spans and structured logs, where they do not create unbounded Prometheus series.

use std::time::Duration;

use metrics::{
    Unit, counter, describe_counter, describe_gauge, describe_histogram, gauge, histogram,
};
use strata_bridge_exec::errors::ExecutorError;
use strata_bridge_sm::{
    deposit::{
        duties::{DepositDuty, NagDuty as DepositNagDuty},
        state::DepositState,
    },
    graph::{
        duties::{GraphDuty, NagDuty as GraphNagDuty},
        state::GraphState,
    },
    stake::{
        duties::{NagDuty as StakeNagDuty, StakeDuty},
        state::StakeState,
    },
};

use crate::{
    errors::{PipelineError, ProcessError},
    events_mux::UnifiedEvent,
    persister::PersistError,
    sm_types::{SMId, UnifiedDuty},
};

const PIPELINE_EVENT_DURATION_SECONDS: &str = "strata_bridge_pipeline_event_duration_seconds";
const PIPELINE_ROUTING_TOTAL: &str = "strata_bridge_pipeline_routing_total";
const SM_TRANSITIONS_TOTAL: &str = "strata_bridge_sm_transitions_total";
const SM_TRANSITION_DURATION_SECONDS: &str = "strata_bridge_sm_transition_duration_seconds";
const DUTIES_TOTAL: &str = "strata_bridge_duties_total";
const DUTIES_IN_FLIGHT: &str = "strata_bridge_duties_in_flight";
const DUTY_DURATION_SECONDS: &str = "strata_bridge_duty_duration_seconds";
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
    describe_counter!(DUTIES_TOTAL, "Duty dispatch and execution outcomes");
    describe_gauge!(
        DUTIES_IN_FLIGHT,
        "Duties currently executing in detached tasks; resets on restart, so durable stuck-duty \
         detection remains the duty tracker's job (STR-2698)"
    );
    describe_histogram!(DUTY_DURATION_SECONDS, Unit::Seconds, "Duty execution time");
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

pub(crate) fn record_duty(
    duty_kind: &'static str,
    result: &'static str,
    error_class: &'static str,
) {
    counter!(
        DUTIES_TOTAL,
        "duty_kind" => duty_kind,
        "result" => result,
        "error_class" => error_class
    )
    .increment(1);
}

/// Marks one duty as executing in a detached task.
pub(crate) fn record_duty_started(duty_kind: &'static str) {
    gauge!(DUTIES_IN_FLIGHT, "duty_kind" => duty_kind).increment(1.0);
}

/// Marks one detached duty task as settled (success, error, or panic).
pub(crate) fn record_duty_settled(duty_kind: &'static str) {
    gauge!(DUTIES_IN_FLIGHT, "duty_kind" => duty_kind).decrement(1.0);
}

pub(crate) fn record_duty_duration(
    duty_kind: &'static str,
    result: &'static str,
    duration: Duration,
) {
    histogram!(
        DUTY_DURATION_SECONDS,
        "duty_kind" => duty_kind,
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

pub(crate) const fn duty_kind(duty: &UnifiedDuty) -> &'static str {
    match duty {
        UnifiedDuty::Deposit(duty) => deposit_duty_kind(duty),
        UnifiedDuty::Graph(duty) => graph_duty_kind(duty),
        UnifiedDuty::Stake(duty) => stake_duty_kind(duty),
    }
}

const fn deposit_duty_kind(duty: &DepositDuty) -> &'static str {
    match duty {
        DepositDuty::PublishDepositNonce { .. } => "publish_deposit_nonce",
        DepositDuty::PublishDepositPartial { .. } => "publish_deposit_partial",
        DepositDuty::PublishDeposit { .. } => "publish_deposit",
        DepositDuty::FulfillWithdrawalRequest { .. } => "fulfill_withdrawal_request",
        DepositDuty::RequestPayoutNonces { .. } => "request_payout_nonces",
        DepositDuty::PublishPayoutNonce { .. } => "publish_payout_nonce",
        DepositDuty::PublishPayoutPartial { .. } => "publish_payout_partial",
        DepositDuty::PublishPayout { .. } => "publish_payout",
        DepositDuty::PublishSweepNonce { .. } => "publish_sweep_nonce",
        DepositDuty::PublishSweepPartial { .. } => "publish_sweep_partial",
        DepositDuty::PublishSweep { .. } => "publish_sweep",
        DepositDuty::Nag { duty } => match duty {
            DepositNagDuty::NagDepositNonce { .. } => "nag_deposit_nonce",
            DepositNagDuty::NagDepositPartial { .. } => "nag_deposit_partial",
            DepositNagDuty::NagPayoutNonce { .. } => "nag_payout_nonce",
            DepositNagDuty::NagPayoutPartial { .. } => "nag_payout_partial",
            DepositNagDuty::NagSweepNonce { .. } => "nag_sweep_nonce",
            DepositNagDuty::NagSweepPartial { .. } => "nag_sweep_partial",
        },
    }
}

const fn graph_duty_kind(duty: &GraphDuty) -> &'static str {
    match duty {
        GraphDuty::GenerateGraphData { .. } => "generate_graph_data",
        GraphDuty::VerifyAdaptors { .. } => "verify_adaptors",
        GraphDuty::PublishGraphNonces { .. } => "publish_graph_nonces",
        GraphDuty::PublishGraphPartials { .. } => "publish_graph_partials",
        GraphDuty::PublishClaim { .. } => "publish_claim",
        GraphDuty::PublishUncontestedPayout { .. } => "publish_uncontested_payout",
        GraphDuty::PublishUnstakingBurn { .. } => "publish_unstaking_burn",
        GraphDuty::PublishContest { .. } => "publish_contest",
        GraphDuty::GenerateAndPublishBridgeProof { .. } => "generate_and_publish_bridge_proof",
        GraphDuty::PublishBridgeProofTimeout { .. } => "publish_bridge_proof_timeout",
        GraphDuty::PotentialCounterProof { .. } => "potential_counter_proof",
        GraphDuty::PublishCounterProofAck { .. } => "publish_counter_proof_ack",
        GraphDuty::PublishCounterProofNack { .. } => "publish_counter_proof_nack",
        GraphDuty::PublishSlash { .. } => "publish_slash",
        GraphDuty::PublishContestedPayout { .. } => "publish_contested_payout",
        GraphDuty::Nag { duty } => match duty {
            GraphNagDuty::NagGraphData { .. } => "nag_graph_data",
            GraphNagDuty::NagGraphNonces { .. } => "nag_graph_nonces",
            GraphNagDuty::NagGraphPartials { .. } => "nag_graph_partials",
        },
    }
}

const fn stake_duty_kind(duty: &StakeDuty) -> &'static str {
    match duty {
        StakeDuty::PublishStakeData { .. } => "publish_stake_data",
        StakeDuty::PublishStake { .. } => "publish_stake",
        StakeDuty::PublishUnstakingNonces { .. } => "publish_unstaking_nonces",
        StakeDuty::PublishUnstakingPartials { .. } => "publish_unstaking_partials",
        StakeDuty::PublishUnstakingIntent { .. } => "publish_unstaking_intent",
        StakeDuty::PublishUnstakingTx { .. } => "publish_unstaking_tx",
        StakeDuty::Nag(duty) => match duty {
            StakeNagDuty::NagUnstakingData { .. } => "nag_unstaking_data",
            StakeNagDuty::NagUnstakingNonces { .. } => "nag_unstaking_nonces",
            StakeNagDuty::NagUnstakingPartials { .. } => "nag_unstaking_partials",
        },
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
        DepositState::SweepNoncesPending { .. } => "sweep_nonces_pending",
        DepositState::SweepNoncesCollected { .. } => "sweep_nonces_collected",
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

pub(crate) const fn executor_error_class(error: &ExecutorError) -> &'static str {
    match error {
        ExecutorError::SecretServiceErr(_) => "secret_service",
        ExecutorError::TxDriverErr(_) => "transaction_driver",
        ExecutorError::OurPubKeyNotInParams => "operator_configuration",
        ExecutorError::SelfVerifyFailed => "signature_self_verification",
        ExecutorError::MissingConfig(_) => "missing_configuration",
        ExecutorError::WalletErr(_) => "wallet",
        ExecutorError::PsbtErr(_) => "psbt",
        ExecutorError::SignatureAggregationFailed(_) => "signature_aggregation",
        ExecutorError::BitcoinRpcErr(_) => "bitcoin_rpc",
        ExecutorError::ClaimTxAlreadyOnChain(_) => "claim_already_on_chain",
        ExecutorError::StakeOutPointAlreadySpent(_) => "stake_already_spent",
        ExecutorError::DatabaseErr(_) => "database",
        ExecutorError::MosaicErr(_) => "mosaic",
        ExecutorError::AsmRpcErr(_) => "asm_rpc",
        ExecutorError::ProofErr(_) => "proof_generation",
        ExecutorError::InvalidTxStructure(_) => "invalid_transaction_structure",
        ExecutorError::FeeRateTooHigh { .. } => "fee_rate_too_high",
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
