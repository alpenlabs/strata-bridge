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
        events::DepositEvent,
        state::DepositState,
    },
    graph::{
        duties::{GraphDuty, NagDuty as GraphNagDuty},
        events::GraphEvent,
        state::GraphState,
    },
    signals::{DepositSignal, DepositToGraph, GraphSignal, GraphToDeposit, Signal},
    stake::{
        duties::{NagDuty as StakeNagDuty, StakeDuty},
        events::StakeEvent,
        state::StakeState,
    },
};

use crate::{
    errors::{PipelineError, ProcessError},
    events_mux::UnifiedEvent,
    persister::PersistError,
    sm_types::{SMEvent, SMId, UnifiedDuty},
};

const PIPELINE_EVENTS_TOTAL: &str = "strata_bridge_pipeline_events_total";
const PIPELINE_EVENT_DURATION_SECONDS: &str = "strata_bridge_pipeline_event_duration_seconds";
const PIPELINE_ROUTING_TOTAL: &str = "strata_bridge_pipeline_routing_total";
const PIPELINE_ROUTING_DURATION_SECONDS: &str = "strata_bridge_pipeline_routing_duration_seconds";
const SM_TRANSITIONS_TOTAL: &str = "strata_bridge_sm_transitions_total";
const SM_TRANSITION_DURATION_SECONDS: &str = "strata_bridge_sm_transition_duration_seconds";
const SIGNALS_TOTAL: &str = "strata_bridge_signals_total";
const DUTIES_TOTAL: &str = "strata_bridge_duties_total";
const DUTIES_IN_FLIGHT: &str = "strata_bridge_duties_in_flight";
const DUTY_DURATION_SECONDS: &str = "strata_bridge_duty_duration_seconds";
const PERSISTENCE_OPERATIONS_TOTAL: &str = "strata_bridge_persistence_operations_total";
const PERSISTENCE_DURATION_SECONDS: &str = "strata_bridge_persistence_duration_seconds";
const PERSISTENCE_BATCH_SIZE: &str = "strata_bridge_persistence_batch_size";
const BLOCK_PROCESSING_DURATION_SECONDS: &str = "strata_bridge_block_processing_duration_seconds";
const BLOCK_TRANSACTIONS: &str = "strata_bridge_block_transactions";
const BLOCK_TX_CLASSIFICATION_DURATION_SECONDS: &str =
    "strata_bridge_block_tx_classification_duration_seconds";
const BLOCK_TX_CLASSIFICATION_STATE_MACHINES: &str =
    "strata_bridge_block_tx_classification_state_machines";
const BLOCK_TX_CLASSIFICATION_MATCHES: &str = "strata_bridge_block_tx_classification_matches";
const P2P_MESSAGES_TOTAL: &str = "strata_bridge_p2p_messages_total";

pub(crate) fn describe_metrics() {
    describe_counter!(
        PIPELINE_EVENTS_TOTAL,
        "Top-level events received by the bridge orchestrator"
    );
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
        PIPELINE_ROUTING_DURATION_SECONDS,
        Unit::Seconds,
        "Time to route and classify one top-level off-chain event"
    );
    describe_counter!(
        SM_TRANSITIONS_TOTAL,
        "State-machine event processing outcomes by bounded state and event kinds"
    );
    describe_histogram!(
        SM_TRANSITION_DURATION_SECONDS,
        Unit::Seconds,
        "State-machine event processing time"
    );
    describe_counter!(
        SIGNALS_TOTAL,
        "Cross-state-machine signals emitted by state transitions"
    );
    describe_counter!(DUTIES_TOTAL, "Duty dispatch and execution outcomes");
    describe_gauge!(
        DUTIES_IN_FLIGHT,
        "Duties currently executing in detached tasks; resets on restart, so durable stuck-duty \
         detection remains the duty tracker's job (STR-2698)"
    );
    describe_histogram!(DUTY_DURATION_SECONDS, Unit::Seconds, "Duty execution time");
    describe_counter!(
        PERSISTENCE_OPERATIONS_TOTAL,
        "Atomic state-machine persistence operation outcomes"
    );
    describe_histogram!(
        PERSISTENCE_DURATION_SECONDS,
        Unit::Seconds,
        "Atomic state-machine persistence operation time"
    );
    describe_histogram!(
        PERSISTENCE_BATCH_SIZE,
        "Number of state machines in one atomic persistence batch"
    );
    describe_histogram!(
        BLOCK_PROCESSING_DURATION_SECONDS,
        Unit::Seconds,
        "Orchestrator processing time for one buried Bitcoin block"
    );
    describe_histogram!(
        BLOCK_TRANSACTIONS,
        "Number of Bitcoin transactions in a processed buried block"
    );
    describe_histogram!(
        BLOCK_TX_CLASSIFICATION_DURATION_SECONDS,
        Unit::Seconds,
        "Time to classify one Bitcoin transaction against all active state machines"
    );
    describe_histogram!(
        BLOCK_TX_CLASSIFICATION_STATE_MACHINES,
        "Number of active state machines checked while classifying one Bitcoin transaction"
    );
    describe_histogram!(
        BLOCK_TX_CLASSIFICATION_MATCHES,
        "Number of state-machine events recognized from one Bitcoin transaction"
    );
    describe_counter!(
        P2P_MESSAGES_TOTAL,
        "P2P message decode and signature-validation outcomes"
    );
}

pub(crate) fn record_pipeline_event_received(event_kind: &'static str) {
    counter!(PIPELINE_EVENTS_TOTAL, "event_kind" => event_kind).increment(1);
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

pub(crate) fn record_routing(event_kind: &'static str, result: &'static str, duration: Duration) {
    counter!(
        PIPELINE_ROUTING_TOTAL,
        "event_kind" => event_kind,
        "result" => result
    )
    .increment(1);
    histogram!(
        PIPELINE_ROUTING_DURATION_SECONDS,
        "event_kind" => event_kind,
        "result" => result
    )
    .record(duration.as_secs_f64());
}

pub(crate) fn record_transition(
    sm_kind: &'static str,
    event_kind: &'static str,
    from_state: &'static str,
    to_state: &'static str,
    result: &'static str,
    duration: Duration,
) {
    counter!(
        SM_TRANSITIONS_TOTAL,
        "sm_kind" => sm_kind,
        "event_kind" => event_kind,
        "from_state" => from_state,
        "to_state" => to_state,
        "result" => result
    )
    .increment(1);
    // The duration distribution deliberately omits `from_state`/`to_state`: transition latency
    // is answered by (sm_kind, event_kind, result), and the state pair would multiply the
    // per-combination distribution series without adding latency information.
    histogram!(
        SM_TRANSITION_DURATION_SECONDS,
        "sm_kind" => sm_kind,
        "event_kind" => event_kind,
        "result" => result
    )
    .record(duration.as_secs_f64());
}

pub(crate) fn record_signal(signal_kind: &'static str) {
    counter!(SIGNALS_TOTAL, "signal_kind" => signal_kind).increment(1);
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
    batch_size: usize,
    duration: Duration,
) {
    counter!(
        PERSISTENCE_OPERATIONS_TOTAL,
        "result" => result,
        "error_class" => error_class
    )
    .increment(1);
    histogram!(PERSISTENCE_DURATION_SECONDS, "result" => result).record(duration.as_secs_f64());
    histogram!(PERSISTENCE_BATCH_SIZE, "result" => result).record(batch_size as f64);
}

pub(crate) fn record_block(result: &'static str, transaction_count: usize, duration: Duration) {
    histogram!(BLOCK_PROCESSING_DURATION_SECONDS, "result" => result)
        .record(duration.as_secs_f64());
    histogram!(BLOCK_TRANSACTIONS).record(transaction_count as f64);
}

pub(crate) fn record_block_tx_classification(
    state_machine_count: usize,
    match_count: usize,
    duration: Duration,
) {
    histogram!(BLOCK_TX_CLASSIFICATION_DURATION_SECONDS).record(duration.as_secs_f64());
    histogram!(BLOCK_TX_CLASSIFICATION_STATE_MACHINES).record(state_machine_count as f64);
    histogram!(BLOCK_TX_CLASSIFICATION_MATCHES).record(match_count as f64);
}

pub(crate) fn record_p2p_message(direction: &'static str, result: &'static str) {
    counter!(
        P2P_MESSAGES_TOTAL,
        "direction" => direction,
        "result" => result
    )
    .increment(1);
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
    }
}

pub(crate) const fn sm_kind(id: &SMId) -> &'static str {
    match id {
        SMId::Deposit(_) => "deposit",
        SMId::Graph(_) => "graph",
        SMId::Stake(_) => "stake",
    }
}

pub(crate) const fn sm_event_kind(event: &SMEvent) -> &'static str {
    match event {
        SMEvent::Deposit(event) => deposit_event_kind(event),
        SMEvent::Graph(event) => graph_event_kind(event),
        SMEvent::Stake(event) => stake_event_kind(event),
    }
}

const fn deposit_event_kind(event: &DepositEvent) -> &'static str {
    match event {
        DepositEvent::UserTakeBack(_) => "user_take_back",
        DepositEvent::GraphMessage(_) => "graph_message",
        DepositEvent::NonceReceived(_) => "nonce_received",
        DepositEvent::PartialReceived(_) => "partial_received",
        DepositEvent::DepositConfirmed(_) => "deposit_confirmed",
        DepositEvent::WithdrawalAssigned(_) => "withdrawal_assigned",
        DepositEvent::FulfillmentConfirmed(_) => "fulfillment_confirmed",
        DepositEvent::PayoutDescriptorReceived(_) => "payout_descriptor_received",
        DepositEvent::PayoutNonceReceived(_) => "payout_nonce_received",
        DepositEvent::PayoutPartialReceived(_) => "payout_partial_received",
        DepositEvent::PayoutConfirmed(_) => "payout_confirmed",
        DepositEvent::NewBlock(_) => "new_block",
        DepositEvent::RetryTick(_) => "retry_tick",
        DepositEvent::NagTick(_) => "nag_tick",
        DepositEvent::NagReceived(_) => "nag_received",
    }
}

const fn graph_event_kind(event: &GraphEvent) -> &'static str {
    match event {
        GraphEvent::GraphDataProduced(_) => "graph_data_produced",
        GraphEvent::DepositMessage(_) => "deposit_message",
        GraphEvent::AdaptorsVerified(_) => "adaptors_verified",
        GraphEvent::NoncesReceived(_) => "nonces_received",
        GraphEvent::PartialsReceived(_) => "partials_received",
        GraphEvent::WithdrawalAssigned(_) => "withdrawal_assigned",
        GraphEvent::FulfillmentConfirmed(_) => "fulfillment_confirmed",
        GraphEvent::ClaimConfirmed(_) => "claim_confirmed",
        GraphEvent::ContestConfirmed(_) => "contest_confirmed",
        GraphEvent::BridgeProofConfirmed(_) => "bridge_proof_confirmed",
        GraphEvent::BridgeProofTimeoutConfirmed(_) => "bridge_proof_timeout_confirmed",
        GraphEvent::CounterProofConfirmed(_) => "counter_proof_confirmed",
        GraphEvent::CounterProofAckConfirmed(_) => "counter_proof_ack_confirmed",
        GraphEvent::CounterProofNackConfirmed(_) => "counter_proof_nack_confirmed",
        GraphEvent::StakeSpent(_) => "stake_spent",
        GraphEvent::PayoutConfirmed(_) => "payout_confirmed",
        GraphEvent::PayoutConnectorSpent(_) => "payout_connector_spent",
        GraphEvent::NewBlock(_) => "new_block",
        GraphEvent::RetryTick(_) => "retry_tick",
        GraphEvent::NagTick(_) => "nag_tick",
        GraphEvent::NagReceived(_) => "nag_received",
    }
}

const fn stake_event_kind(event: &StakeEvent) -> &'static str {
    match event {
        StakeEvent::StakeDataReceived(_) => "stake_data_received",
        StakeEvent::UnstakingNoncesReceived(_) => "unstaking_nonces_received",
        StakeEvent::UnstakingPartialsReceived(_) => "unstaking_partials_received",
        StakeEvent::StakeConfirmed(_) => "stake_confirmed",
        StakeEvent::PreimageRevealed(_) => "preimage_revealed",
        StakeEvent::UnstakingConfirmed(_) => "unstaking_confirmed",
        StakeEvent::SlashConfirmed(_) => "slash_confirmed",
        StakeEvent::NewBlock(_) => "new_block",
        StakeEvent::RetryTick(_) => "retry_tick",
        StakeEvent::NagTick(_) => "nag_tick",
        StakeEvent::NagReceived(_) => "nag_received",
    }
}

pub(crate) const fn duty_kind(duty: &UnifiedDuty) -> &'static str {
    match duty {
        UnifiedDuty::Deposit(duty) => deposit_duty_kind(duty),
        UnifiedDuty::Graph(duty) => graph_duty_kind(duty),
        UnifiedDuty::Stake(duty) => stake_duty_kind(duty),
    }
}

/// Returns the duty's intentionally redacted display form for spans and logs.
///
/// The derived `Debug` representation can contain signing material, proofs, and an unstaking
/// preimage. The concrete duty `Display` implementations expose only operationally safe context.
pub(crate) fn duty_context(duty: &UnifiedDuty) -> String {
    match duty {
        UnifiedDuty::Deposit(duty) => duty.to_string(),
        UnifiedDuty::Graph(duty) => duty.to_string(),
        UnifiedDuty::Stake(duty) => duty.to_string(),
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
        DepositDuty::Nag { duty } => match duty {
            DepositNagDuty::NagDepositNonce { .. } => "nag_deposit_nonce",
            DepositNagDuty::NagDepositPartial { .. } => "nag_deposit_partial",
            DepositNagDuty::NagPayoutNonce { .. } => "nag_payout_nonce",
            DepositNagDuty::NagPayoutPartial { .. } => "nag_payout_partial",
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
        GraphDuty::GenerateAndPublishCounterProof { .. } => "generate_and_publish_counter_proof",
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

pub(crate) const fn signal_kind(signal: &Signal) -> &'static str {
    match signal {
        Signal::FromDeposit(DepositSignal::ToGraph(signal)) => match signal {
            DepositToGraph::CooperativePayoutFailed { .. } => "cooperative_payout_failed",
            DepositToGraph::DepositRequestTakenBack { .. } => "deposit_request_taken_back",
        },
        Signal::FromGraph(GraphSignal::ToDeposit(GraphToDeposit::GraphAvailable { .. })) => {
            "graph_available"
        }
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
        PipelineError::InternalInvariant(_) => "pipeline_invariant",
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
