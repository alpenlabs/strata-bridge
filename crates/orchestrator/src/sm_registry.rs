//! The state machine registry: stores all active state machines and provides methods for
//! querying, resolving operators, and driving state transitions.

use std::{
    collections::{BTreeMap, btree_map::Entry},
    fmt::{Debug, Display},
    sync::Arc,
    time::Instant,
};

use bitcoin::{
    OutPoint,
    hashes::{Hash, sha256},
};
use strata_asm_bridge_types::SafeHarbourAddress;
use strata_bridge_primitives::{
    covenant::{CovenantId, StakeKey},
    operator_table::OperatorTable,
    types::{DepositIdx, GraphIdx, OperatorIdx},
};
use strata_bridge_sm::{
    cross_sm_context::CrossSmContext,
    deposit::{config::DepositSMCfg, events::DepositEvent, machine::DepositSM},
    errors::BridgeSMError,
    graph::{config::GraphSMCfg, events::GraphEvent, machine::GraphSM},
    operator_set::{OperatorSetError, OperatorSetEvent, OperatorSetSM},
    signals,
    stake::{config::StakeSMCfg, events::StakeEvent, machine::StakeSM, state::StakeState},
    state_machine::{SMOutput, StateMachine},
};
use strata_bridge_tx_graph::transactions::stake::StakeTx;
use thiserror::Error;
use tracing::{debug, error, info, info_span};

use crate::{
    errors::{ProcessError, ProcessOutput},
    observability,
    sm_types::{OperatorKey, SMEvent, SMId, UnifiedDuty},
};

/// Static configuration shared by all state machines.
#[derive(Debug, Clone)]
pub struct SMConfig {
    /// Static configuration for all deposit state machines.
    pub deposit: Arc<DepositSMCfg>,
    /// Static configuration for all graph state machines.
    pub graph: Arc<GraphSMCfg>,
    /// Static configuration for all stake state machines.
    pub stake: Arc<StakeSMCfg>,
}

/// The registry that holds all the active state machines in `strata-bridge`.
#[derive(Debug, Clone)]
pub struct SMRegistry {
    /// Static configuration shared by all state machines.
    cfg: SMConfig,
    /// The state machines responsible for processing deposits, indexed by their deposit index.
    deposits: BTreeMap<DepositIdx, DepositSM>,
    /// The state machines responsible for processing graphs, indexed by their graph index.
    // NOTE: (@Rajil1213) if performance becomes an issue when looking up graph state machines by
    // deposit index, change this to a `BTreeMap<DepositIdx, BTreeMap<OperatorIdx, GraphSM>>` or
    // maintain a separate index for that mapping.
    graphs: BTreeMap<GraphIdx, GraphSM>,
    /// Independent stake instances, indexed by covenant and permanent operator index.
    stakes: BTreeMap<StakeKey, StakeSM>,
    /// Public membership, installed once by bootstrap or restored from storage.
    // TODO: <https://alpenlabs.atlassian.net/browse/STR-3621>
    // Initialize membership during startup reconciliation and make this field required.
    operator_set: Option<OperatorSetSM>,
    /// The latched safe-harbour destination address, set once when the ASM reports the safe
    /// harbour as activated. This is sticky and monotonic: the first write wins and it is never
    /// cleared, so it survives a tip reorg that flips the ASM flag back to inactive. `None` means
    /// safe harbour has not been observed as activated on this node.
    safe_harbour: Option<SafeHarbourAddress>,
}

/// Invariant errors when inserting state machines into the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RegistryInsertError {
    /// A deposit SM already exists at this key.
    #[error("deposit state machine already exists at index {0}")]
    DepositAlreadyExists(DepositIdx),
    /// A graph SM already exists at this key.
    #[error("graph state machine already exists at index {0:?}")]
    GraphAlreadyExists(GraphIdx),
    /// A stake SM already exists at this covenant-qualified key.
    #[error("stake state machine already exists for operator {0}")]
    StakeAlreadyExists(StakeKey),
    /// Equal identities must have the same full indexed membership.
    #[error("conflicting membership for stake {0}")]
    CovenantMembershipMismatch(StakeKey),
    /// The maximum deposit index has been reached.
    #[error("deposit index exhausted at {0}; cannot allocate a new deposit index")]
    DepositIdxExhausted(DepositIdx),
    /// Public membership was already installed; existing history must not be overwritten.
    #[error("operator set state machine already exists")]
    OperatorSetAlreadyExists,
}

/// Confirmed stake inputs for the full, exact membership of a requested covenant.
#[derive(Debug, Clone)]
pub struct ActiveOperatorSnapshot {
    /// The covenant whose members have all confirmed their stakes.
    pub covenant: CovenantId,
    /// The complete operator table; local readiness never filters membership.
    pub operator_table: OperatorTable,
    /// The stake output bound to each operator's graph.
    pub stake_inputs: BTreeMap<OperatorIdx, OutPoint>,
    /// The unstaking image bound to each operator's graph.
    pub unstaking_images: BTreeMap<OperatorIdx, sha256::Hash>,
}

/// Errors returned when constructing an [`ActiveOperatorSnapshot`].
#[derive(Debug, Clone, Error)]
pub enum SnapshotError {
    /// The requested covenant is missing a member's stake instance.
    #[error("missing stake state machine for {0}")]
    MissingStakeSM(StakeKey),
    /// A member's stake has not confirmed or is no longer available.
    #[error("stake unavailable for {0}")]
    StakeUnavailable(StakeKey),
    /// The supplied membership disagrees with the requested covenant or a stored context.
    #[error("covenant membership mismatch for {0}")]
    CovenantMembershipMismatch(CovenantId),
}

/// Reason why a state machine event was ignored as non-fatal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IgnoredEventReason {
    /// The event was a duplicate of previously-processed input.
    Duplicate,
    /// The event was rejected because it is no longer relevant.
    Rejected(String),
}

/// Outcome from processing an event through a state machine.
#[derive(Debug, Clone)]
pub enum ProcessOutcome {
    /// The event was applied successfully and produced output.
    Applied(ProcessOutput),
    /// The event was ignored as a known non-fatal condition.
    Ignored {
        /// The state machine that received the ignored event.
        id: SMId,
        /// The event that was ignored.
        event: SMEvent,
        /// Why the event was ignored.
        reason: IgnoredEventReason,
    },
}

impl SMRegistry {
    /// Creates a new empty registry with the given configuration.
    pub const fn new(cfg: SMConfig) -> Self {
        Self {
            cfg,
            deposits: BTreeMap::new(),
            graphs: BTreeMap::new(),
            stakes: BTreeMap::new(),
            operator_set: None,
            safe_harbour: None,
        }
    }

    /// Gets a reference to the registry configuration.
    pub const fn cfg(&self) -> &SMConfig {
        &self.cfg
    }

    // ── Safe Harbour ──────────────────────────────────────────────────

    /// Latches the frozen safe-harbour `address` on the first activation.
    ///
    /// Monotonic: the first write wins and subsequent calls are no-ops, even with a different
    /// address. This is what makes the flag reorg-safe — once a node has observed activation it
    /// stays in safe-harbour mode regardless of what the (non-final) ASM tip later reports.
    ///
    /// Returns `true` if this call latched the address (i.e. it was the first activation), and
    /// `false` if the safe harbour was already latched.
    pub fn activate_safe_harbour(&mut self, address: SafeHarbourAddress) -> bool {
        if self.safe_harbour.is_some() {
            return false;
        }
        self.safe_harbour = Some(address);
        true
    }

    /// Returns the latched safe-harbour address, or `None` if safe harbour is not active.
    pub const fn safe_harbour_address(&self) -> Option<&SafeHarbourAddress> {
        self.safe_harbour.as_ref()
    }

    /// Returns `true` iff safe harbour has been latched on this node.
    pub const fn safe_harbour_active(&self) -> bool {
        self.safe_harbour.is_some()
    }

    /// Gets the total number of deposit state machines currently in the registry.
    pub fn num_deposits(&self) -> usize {
        self.deposits.len()
    }

    /// Gets the total number of stake state machines currently in the registry.
    pub fn num_stakes(&self) -> usize {
        self.stakes.len()
    }

    /// Gets a list of IDs of all deposit state machines currently in the registry.
    pub fn get_deposit_ids(&self) -> Vec<DepositIdx> {
        self.deposits.keys().copied().collect()
    }

    /// Gets a list of IDs of all graph state machines currently in the registry.
    pub fn get_graph_ids(&self) -> Vec<GraphIdx> {
        self.graphs.keys().copied().collect()
    }

    /// Gets the covenant-qualified keys of all stake state machines.
    pub fn get_stake_ids(&self) -> Vec<StakeKey> {
        self.stakes.keys().copied().collect()
    }

    /// Gets the IDs of all the state machines currently in the registry.
    pub fn get_all_ids(&self) -> Vec<SMId> {
        self.deposits
            .keys()
            .map(|deposit_idx| SMId::Deposit(*deposit_idx))
            .chain(self.graphs.keys().map(|graph_idx| SMId::Graph(*graph_idx)))
            .chain(self.stakes.keys().map(|op_idx| SMId::Stake(*op_idx)))
            .chain(self.operator_set.as_ref().map(|_| SMId::OperatorSet))
            .collect()
    }

    /// Installs the singleton membership component without replacing an existing history.
    pub fn insert_operator_set(&mut self, sm: OperatorSetSM) -> Result<(), RegistryInsertError> {
        if self.operator_set.is_some() {
            return Err(RegistryInsertError::OperatorSetAlreadyExists);
        }
        self.operator_set = Some(sm);
        Ok(())
    }

    /// The finalized public membership view, independent of local StakeSM availability.
    pub const fn get_operator_set(&self) -> Option<&OperatorSetSM> {
        self.operator_set.as_ref()
    }

    /// Gets a reference to the deposit state machine identified by `id`, if it exists in the
    /// registry.
    pub fn get_deposit(&self, deposit_idx: &DepositIdx) -> Option<&DepositSM> {
        self.deposits.get(deposit_idx)
    }

    /// Gets a reference to the graph state machine identified by `id`, if it exists in the
    /// registry.
    pub fn get_graph(&self, graph_idx: &GraphIdx) -> Option<&GraphSM> {
        self.graphs.get(graph_idx)
    }

    /// Resolves an operator-only legacy message only when there is exactly one stake instance.
    /// Ambiguous messages are rejected until covenant-qualified wire messages are available.
    ///
    /// Temporary compatibility shim for operator-only callers. Replace these lookups with explicit
    /// [`StakeKey`] lookups as storage ([STR-4043](https://alpenlabs.atlassian.net/browse/STR-4043)),
    /// P2P messages ([STR-4044](https://alpenlabs.atlassian.net/browse/STR-4044)), and RPCs
    /// ([STR-3625](https://alpenlabs.atlassian.net/browse/STR-3625)) adopt covenant-qualified identities.
    pub fn resolve_legacy_stake_key(&self, operator: OperatorIdx) -> Option<StakeKey> {
        let mut candidates = self.stakes.keys().filter(|key| key.operator == operator);
        let key = *candidates.next()?;
        candidates.next().is_none().then_some(key)
    }

    /// Resolves a validated observation's source stake output without interpreting exit rules.
    /// Missing or ambiguous sources do not resolve to a local instance.
    pub fn resolve_stake_outpoint(&self, source: &OutPoint) -> Option<StakeKey> {
        let mut matches = self.stakes.iter().filter_map(|(key, sm)| {
            let stake_txid = sm.state().stake_txid()?;
            (OutPoint::new(stake_txid, StakeTx::STAKE_VOUT) == *source).then_some(*key)
        });
        let key = matches.next()?;
        matches.next().is_none().then_some(key)
    }

    /// Looks up an exact covenant-qualified stake instance.
    pub fn get_stake(&self, operator_idx: &StakeKey) -> Option<&StakeSM> {
        self.stakes.get(operator_idx)
    }

    /// Returns an iterator over all deposit state machines and their indices.
    pub fn deposits(&self) -> impl Iterator<Item = (&DepositIdx, &DepositSM)> {
        self.deposits.iter()
    }

    /// Returns an iterator over all graph state machines and their indices.
    pub fn graphs(&self) -> impl Iterator<Item = (&GraphIdx, &GraphSM)> {
        self.graphs.iter()
    }

    /// Returns an iterator over all stake state machines and their operator indices.
    pub fn stakes(&self) -> impl Iterator<Item = (&StakeKey, &StakeSM)> {
        self.stakes.iter()
    }

    /// Checks if an ID is present in the registry.
    pub fn contains_id(&self, id: &SMId) -> bool {
        match id {
            SMId::OperatorSet => self.operator_set.is_some(),
            SMId::Deposit(deposit_idx) => self.deposits.contains_key(deposit_idx),
            SMId::Graph(graph_idx) => self.graphs.contains_key(graph_idx),
            SMId::Stake(operator_idx) => self.stakes.contains_key(operator_idx),
        }
    }

    /// Returns the next available deposit index (`max(existing) + 1`).
    pub fn next_deposit_idx(&self) -> Result<DepositIdx, RegistryInsertError> {
        self.deposits
            .keys()
            .next_back() // works because this is a BTreeMap sorted by keys
            .copied()
            .map_or(Ok(0), |max_idx| {
                max_idx
                    .checked_add(1)
                    .ok_or(RegistryInsertError::DepositIdxExhausted(max_idx))
            })
    }

    /// Inserts a new deposit state machine into the registry with the given deposit index.
    ///
    /// Returns an error if a state machine with the same [`DepositIdx`] already exists.
    pub fn insert_deposit(
        &mut self,
        deposit_idx: DepositIdx,
        sm: DepositSM,
    ) -> Result<(), RegistryInsertError> {
        match self.deposits.entry(deposit_idx) {
            Entry::Vacant(entry) => {
                entry.insert(sm);
                Ok(())
            }
            Entry::Occupied(_) => {
                error!(
                    "Duplicate DepositSM insertion attempted for index {}",
                    deposit_idx
                );
                Err(RegistryInsertError::DepositAlreadyExists(deposit_idx))
            }
        }
    }

    /// Inserts a new graph state machine into the registry with the given graph index.
    ///
    /// Returns an error if a state machine with the same [`GraphIdx`] already exists.
    pub fn insert_graph(
        &mut self,
        graph_idx: GraphIdx,
        sm: GraphSM,
    ) -> Result<(), RegistryInsertError> {
        match self.graphs.entry(graph_idx) {
            Entry::Vacant(entry) => {
                entry.insert(sm);
                Ok(())
            }
            Entry::Occupied(_) => {
                error!(
                    "Duplicate GraphSM insertion attempted for index {:?}",
                    graph_idx
                );
                Err(RegistryInsertError::GraphAlreadyExists(graph_idx))
            }
        }
    }

    /// Inserts a stake under its immutable context identity.
    ///
    /// Rejects duplicate identities and conflicting indexed membership for the same covenant.
    pub fn insert_stake(&mut self, sm: StakeSM) -> Result<(), RegistryInsertError> {
        let operator_idx = sm.context().stake_key();
        if self.stakes.values().any(|existing| {
            existing.context().stake_key().covenant == operator_idx.covenant
                && !existing
                    .context()
                    .operator_table()
                    .has_same_membership(sm.context().operator_table())
        }) {
            return Err(RegistryInsertError::CovenantMembershipMismatch(
                operator_idx,
            ));
        }
        match self.stakes.entry(operator_idx) {
            Entry::Vacant(entry) => {
                entry.insert(sm);
                Ok(())
            }
            Entry::Occupied(_) => {
                error!(
                    "Duplicate StakeSM insertion attempted for operator {}",
                    operator_idx
                );
                Err(RegistryInsertError::StakeAlreadyExists(operator_idx))
            }
        }
    }

    /// Returns whether this exact stake is available for new deposits.
    pub fn is_operator_active_for_new_deposits(&self, key: &StakeKey) -> bool {
        self.stakes
            .get(key)
            .is_some_and(|sm| sm.state().is_stake_available())
    }

    /// Collects confirmed stakes for the complete requested covenant.
    /// Missing or unavailable members keep readiness closed; a subset never forms a covenant.
    pub fn active_operator_snapshot(
        &self,
        covenant: CovenantId,
        full_table: &OperatorTable,
    ) -> Result<ActiveOperatorSnapshot, SnapshotError> {
        if CovenantId::from_operator_table(full_table, covenant.activation_height) != Ok(covenant) {
            return Err(SnapshotError::CovenantMembershipMismatch(covenant));
        }
        let mut stake_inputs = BTreeMap::new();
        let mut unstaking_images = BTreeMap::new();
        for operator in full_table.operator_idxs() {
            let key = StakeKey { covenant, operator };
            let ssm = self
                .stakes
                .get(&key)
                .ok_or(SnapshotError::MissingStakeSM(key))?;
            if !ssm
                .context()
                .operator_table()
                .has_same_membership(full_table)
            {
                return Err(SnapshotError::CovenantMembershipMismatch(covenant));
            }
            let StakeState::Confirmed {
                stake_data,
                summary,
                ..
            } = ssm.state()
            else {
                return Err(SnapshotError::StakeUnavailable(key));
            };
            stake_inputs.insert(operator, OutPoint::new(summary.stake, StakeTx::STAKE_VOUT));
            unstaking_images.insert(operator, stake_data.unstaking_image);
        }
        Ok(ActiveOperatorSnapshot {
            covenant,
            operator_table: full_table.clone(),
            stake_inputs,
            unstaking_images,
        })
    }

    /// Looks up the state machine identified by `id` and resolves the operator index using the
    /// given [`OperatorKey`].
    ///
    /// Returns `None` if the SM is not in the registry or the operator key cannot be resolved.
    pub fn lookup_operator(&self, id: &SMId, key: &OperatorKey<'_>) -> Option<OperatorIdx> {
        let table = match id {
            // Public membership has no local signing role or peer-message protocol.
            SMId::OperatorSet => return None,
            SMId::Deposit(idx) => self.deposits.get(idx)?.context().operator_table(),
            SMId::Graph(idx) => self.graphs.get(idx)?.context().operator_table(),
            SMId::Stake(idx) => self.stakes.get(idx)?.context().operator_table(),
        };
        match key {
            OperatorKey::Pov => Some(table.pov_idx()),
            OperatorKey::Peer(p2p_key) => table.p2p_key_to_idx(p2p_key),
        }
    }

    /// Processes an event through the state machine identified by `id`.
    ///
    /// Looks up the SM, matches it against the event variant, runs the state transition, and
    /// returns unified output. The caller does not need to know the concrete SM type.
    pub fn process_event(
        &mut self,
        id: &SMId,
        event: SMEvent,
    ) -> Result<ProcessOutcome, ProcessError> {
        let sm_kind = observability::sm_kind(id);
        let is_periodic = is_periodic_event(&event);
        let from_state = self.state_kind(id).unwrap_or("missing");
        // Info-level so the transition span exists under the default INFO filter; span creation
        // emits no log lines, and the per-tick log statements below stay at debug.
        let span = info_span!(
            "bridge_sm_transition",
            sm_kind,
            sm_id = %id,
            event = %event,
            from_state,
            to_state = tracing::field::Empty,
            result = tracing::field::Empty,
        );
        let _entered = span.enter();
        let started = Instant::now();
        let outcome = self.process_event_inner(id, event);
        let to_state = self.state_kind(id).unwrap_or("missing");
        let result = transition_result(&outcome);

        span.record("to_state", to_state);
        span.record("result", result);
        observability::record_transition(sm_kind, from_state, to_state, result, started.elapsed());

        // Keep transition telemetry here, but leave ignored-outcome and fatal-error severity to
        // the applicator and pipeline respectively.
        match &outcome {
            Ok(ProcessOutcome::Applied(output)) if output.did_mutate() && is_periodic => {
                debug!(
                    sm_kind,
                    sm_id = %id,
                    from_state,
                    to_state,
                    duty_count = output.duties.len(),
                    signal_count = output.signals.len(),
                    "periodic state-machine transition applied"
                );
            }
            Ok(ProcessOutcome::Applied(output)) if output.did_mutate() => {
                info!(
                    sm_kind,
                    sm_id = %id,
                    from_state,
                    to_state,
                    duty_count = output.duties.len(),
                    signal_count = output.signals.len(),
                    "state-machine transition applied"
                );
            }
            Ok(ProcessOutcome::Applied(_)) | Ok(ProcessOutcome::Ignored { .. }) | Err(_) => {}
        }

        outcome
    }

    fn process_event_inner(
        &mut self,
        id: &SMId,
        event: SMEvent,
    ) -> Result<ProcessOutcome, ProcessError> {
        let cross_sm_context = self.resolve_cross_sm_context(id);

        match (id, event) {
            (SMId::OperatorSet, SMEvent::OperatorSet(event)) => {
                let sm = self
                    .operator_set
                    .as_mut()
                    .ok_or(ProcessError::SMNotFound(*id))?;
                let original = SMEvent::OperatorSet(event.clone());
                match sm.process_event((), *event) {
                    Ok(output) => Ok(applied_process_outcome(output, |duty| match duty {})),
                    Err(OperatorSetError::NonconsecutiveBlock {
                        processed,
                        received,
                    }) if processed == received => Ok(ProcessOutcome::Ignored {
                        id: *id,
                        event: original,
                        reason: IgnoredEventReason::Duplicate,
                    }),
                    Err(error) => Err(error.into()),
                }
            }
            (SMId::Deposit(idx), SMEvent::Deposit(deposit_event)) => {
                let sm = self
                    .deposits
                    .get_mut(idx)
                    .ok_or(ProcessError::SMNotFound(*id))?;
                let event = SMEvent::Deposit(deposit_event.clone());
                sm.process_event(self.cfg.deposit.clone(), *deposit_event)
                    .map(|out| {
                        let mut out = out;
                        out.duties
                            .extend(sm.run_post_stf_hook(&self.cfg.deposit, &cross_sm_context));
                        applied_process_outcome(out, UnifiedDuty::Deposit)
                    })
                    .or_else(|err| process_result_from_sm_error(id, event, err))
            }

            (SMId::Graph(idx), SMEvent::Graph(graph_event)) => {
                let sm = self
                    .graphs
                    .get_mut(idx)
                    .ok_or(ProcessError::SMNotFound(*id))?;
                let event = SMEvent::Graph(graph_event.clone());
                sm.process_event(self.cfg.graph.clone(), *graph_event)
                    .map(|out| {
                        let mut out = out;
                        out.duties
                            .extend(sm.run_post_stf_hook(&self.cfg.graph, &cross_sm_context));
                        applied_process_outcome(out, UnifiedDuty::Graph)
                    })
                    .or_else(|err| process_result_from_sm_error(id, event, err))
            }

            (SMId::Stake(idx), SMEvent::Stake(stake_event)) => {
                let sm = self
                    .stakes
                    .get_mut(idx)
                    .ok_or(ProcessError::SMNotFound(*id))?;
                let event = SMEvent::Stake(stake_event.clone());
                sm.process_event(self.cfg.stake.clone(), *stake_event)
                    .map(|out| {
                        let mut out = out;
                        out.duties
                            .extend(sm.run_post_stf_hook(&self.cfg.stake, &cross_sm_context));
                        applied_process_outcome(out, |duty| UnifiedDuty::Stake {
                            stake_key: sm.context().stake_key(),
                            duty,
                        })
                    })
                    .or_else(|err| process_result_from_sm_error(id, event, err))
            }

            (id, event) => Err(ProcessError::InvalidInvocation(*id, event)),
        }
    }

    fn state_kind(&self, id: &SMId) -> Option<&'static str> {
        match id {
            SMId::OperatorSet => self.operator_set.as_ref().map(|_| "tracking"),
            SMId::Deposit(idx) => self
                .deposits
                .get(idx)
                .map(|sm| observability::deposit_state_kind(sm.state())),
            SMId::Graph(idx) => self
                .graphs
                .get(idx)
                .map(|sm| observability::graph_state_kind(sm.state())),
            SMId::Stake(idx) => self
                .stakes
                .get(idx)
                .map(|sm| observability::stake_state_kind(sm.state())),
        }
    }

    /// Resolves auxiliary state from sibling state machines for the destination `id`.
    ///
    /// This context is intentionally not routed as a signal: resolving it does not create a
    /// causal persistence edge from the source SM to the destination SM.
    fn resolve_cross_sm_context(&self, id: &SMId) -> CrossSmContext {
        match id {
            SMId::Graph(graph_idx) => self.resolve_graph_cross_sm_context(graph_idx),
            SMId::Deposit(_) | SMId::Stake(_) | SMId::OperatorSet => CrossSmContext::default(),
        }
    }

    /// Resolves context needed by a graph state machine from its owner's stake state machine.
    fn resolve_graph_cross_sm_context(&self, graph_idx: &GraphIdx) -> CrossSmContext {
        let Some(graph_sm) = self.graphs.get(graph_idx) else {
            return CrossSmContext::default();
        };

        self.stakes
            .get(&graph_sm.context().stake_key())
            .filter(|stake_sm| {
                stake_sm
                    .context()
                    .operator_table()
                    .has_same_membership(graph_sm.context().operator_table())
            })
            .and_then(|stake_sm| {
                let preimage = stake_sm.state().preimage()?;
                (sha256::Hash::hash(&preimage) == graph_sm.context().unstaking_image())
                    .then_some(preimage)
            })
            .map_or_else(
                CrossSmContext::default,
                CrossSmContext::with_unstaking_preimage,
            )
    }
}

const fn transition_result(outcome: &Result<ProcessOutcome, ProcessError>) -> &'static str {
    match outcome {
        Ok(ProcessOutcome::Applied(output)) if output.did_mutate() => "applied_mutated",
        Ok(ProcessOutcome::Applied(_)) => "applied_unchanged",
        Ok(ProcessOutcome::Ignored {
            reason: IgnoredEventReason::Duplicate,
            ..
        }) => "duplicate",
        Ok(ProcessOutcome::Ignored {
            reason: IgnoredEventReason::Rejected(_),
            ..
        }) => "rejected",
        Err(_) => "invalid",
    }
}

fn is_periodic_event(event: &SMEvent) -> bool {
    match event {
        SMEvent::OperatorSet(event) => matches!(event.as_ref(), OperatorSetEvent::NewBlock { .. }),
        SMEvent::Deposit(event) => matches!(
            event.as_ref(),
            DepositEvent::NewBlock(_) | DepositEvent::RetryTick(_) | DepositEvent::NagTick(_)
        ),
        SMEvent::Graph(event) => matches!(
            event.as_ref(),
            GraphEvent::NewBlock(_) | GraphEvent::RetryTick(_) | GraphEvent::NagTick(_)
        ),
        SMEvent::Stake(event) => matches!(
            event.as_ref(),
            StakeEvent::NewBlock(_) | StakeEvent::RetryTick(_) | StakeEvent::NagTick(_)
        ),
    }
}

fn applied_process_outcome<D, S, MapDuty>(out: SMOutput<D, S>, map_duty: MapDuty) -> ProcessOutcome
where
    S: Into<signals::Signal>,
    MapDuty: FnMut(D) -> UnifiedDuty,
{
    let did_mutate = out.did_mutate();
    let output: ProcessOutput = SMOutput::with_duties_and_signals(
        out.duties.into_iter().map(map_duty).collect(),
        out.signals.into_iter().map(Into::into).collect(),
    );

    let output = if did_mutate {
        output
    } else {
        output.mark_unchanged()
    };

    ProcessOutcome::Applied(output)
}

fn process_result_from_sm_error<S, E>(
    id: &SMId,
    event: SMEvent,
    err: BridgeSMError<S, E>,
) -> Result<ProcessOutcome, ProcessError>
where
    S: Display + Debug,
    E: Display + Debug,
{
    match err {
        BridgeSMError::InvalidEvent { reason, state, .. } => Err(ProcessError::InvariantViolation(
            Box::new(*id),
            event,
            state.to_string(),
            reason.unwrap_or_else(|| "invalid event".to_string()),
        )),
        BridgeSMError::Duplicate { .. } => Ok(ProcessOutcome::Ignored {
            id: *id,
            event,
            reason: IgnoredEventReason::Duplicate,
        }),
        BridgeSMError::Rejected { reason, .. } => Ok(ProcessOutcome::Ignored {
            id: *id,
            event,
            reason: IgnoredEventReason::Rejected(reason),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZero;

    use bitcoin::{OutPoint, hashes::Hash, key::rand};
    use strata_bridge_p2p_types::NagRequestPayload;
    use strata_bridge_primitives::types::{GraphIdx, P2POperatorPubKey};
    use strata_bridge_sm::{
        deposit::events::{DepositEvent, NagReceivedEvent, NewBlockEvent as DepositNewBlock},
        graph::{
            duties::GraphDuty,
            events::{GraphEvent, NewBlockEvent as GraphNewBlock},
            machine::generate_game_graph,
            state::GraphState,
        },
        stake::context::StakeSMCtx,
    };
    use strata_bridge_test_utils::{bitcoin::generate_xonly_pubkey, prelude::generate_txid};
    use strata_bridge_tx_graph::game_graph::DepositParams;

    use super::*;
    use crate::{
        sm_types::OperatorKey,
        testing::{
            INITIAL_BLOCK_HEIGHT, N_TEST_OPERATORS, TEST_POV_IDX, insert_confirmed_stake,
            insert_created_stake, insert_deposit_with_graphs, make_confirmed_stake_sm,
            test_empty_registry, test_operator_table, test_populated_registry,
        },
    };

    // ===== Basic CRUD tests =====

    #[test]
    fn new_registry_is_empty() {
        let registry = test_empty_registry();
        assert_eq!(registry.num_deposits(), 0);
        assert!(registry.get_all_ids().is_empty());
    }

    // ===== Safe-harbour latch tests =====

    /// Builds a P2TR [`SafeHarbourAddress`] from a 32-byte x-only pubkey payload.
    ///
    /// `new_p2tr` rejects payloads that are not valid on-curve x-coordinates (only ~half of all
    /// 32-byte values are), so `a`/`b` below use fills known to be valid; e.g. `[3u8; 32]` is not.
    fn safe_harbour_address(payload: [u8; 32]) -> SafeHarbourAddress {
        let descriptor =
            bitcoin_bosd::Descriptor::new_p2tr(&payload).expect("valid x-only public key");
        SafeHarbourAddress::try_from(descriptor).expect("p2tr descriptor accepted")
    }

    fn safe_harbour_address_a() -> SafeHarbourAddress {
        safe_harbour_address([2u8; 32])
    }

    fn safe_harbour_address_b() -> SafeHarbourAddress {
        safe_harbour_address([7u8; 32])
    }

    #[test]
    fn safe_harbour_defaults_to_inactive() {
        let registry = test_empty_registry();
        assert!(!registry.safe_harbour_active());
        assert_eq!(registry.safe_harbour_address(), None);
    }

    #[test]
    fn activate_safe_harbour_latches_address() {
        let mut registry = test_empty_registry();
        let address = safe_harbour_address_a();

        assert!(
            registry.activate_safe_harbour(address.clone()),
            "first activation must report it latched"
        );
        assert!(registry.safe_harbour_active());
        assert_eq!(registry.safe_harbour_address(), Some(&address));
    }

    #[test]
    fn activate_safe_harbour_is_monotonic_first_write_wins() {
        // Models the reorg/convergence property: once a node has latched the activation, a later
        // observation (even one carrying a different address) must not change or clear the latch.
        let mut registry = test_empty_registry();
        let first = safe_harbour_address_a();
        let second = safe_harbour_address_b();
        assert_ne!(first, second);

        assert!(registry.activate_safe_harbour(first.clone()));
        assert!(
            !registry.activate_safe_harbour(second),
            "a subsequent activation must be a no-op and report it did not latch"
        );

        assert!(registry.safe_harbour_active());
        assert_eq!(
            registry.safe_harbour_address(),
            Some(&first),
            "the originally latched address must be preserved"
        );
    }

    #[test]
    fn next_deposit_idx_empty_is_zero() {
        let registry = test_empty_registry();
        assert_eq!(registry.next_deposit_idx(), Ok(0));
    }

    #[test]
    fn insert_and_get_deposit() {
        let registry = test_populated_registry(1);
        assert!(registry.get_deposit(&0).is_some());
    }

    #[test]
    fn insert_and_get_graph() {
        let registry = test_populated_registry(1);
        let gidx = GraphIdx {
            deposit: 0,
            operator: 0,
        };
        assert!(registry.get_graph(&gidx).is_some());
    }

    #[test]
    fn insert_deposit_duplicate_returns_error_and_preserves_original() {
        let mut registry = test_populated_registry(1);
        let duplicate = registry
            .get_deposit(&0)
            .expect("fixture must contain deposit 0")
            .clone();

        let result = registry.insert_deposit(0, duplicate);
        assert_eq!(result, Err(RegistryInsertError::DepositAlreadyExists(0)));
        assert_eq!(registry.num_deposits(), 1);
        assert!(registry.get_deposit(&0).is_some());
    }

    #[test]
    fn insert_graph_duplicate_returns_error_and_preserves_original() {
        let mut registry = test_populated_registry(1);
        let gidx = GraphIdx {
            deposit: 0,
            operator: 0,
        };
        let duplicate = registry
            .get_graph(&gidx)
            .expect("fixture must contain graph (0, 0)")
            .clone();

        let result = registry.insert_graph(gidx, duplicate);
        assert_eq!(result, Err(RegistryInsertError::GraphAlreadyExists(gidx)));
        assert_eq!(registry.get_graph_ids().len(), N_TEST_OPERATORS);
        assert!(registry.get_graph(&gidx).is_some());
    }

    #[test]
    fn next_deposit_idx_non_empty_is_max_plus_one() {
        let registry = test_populated_registry(3);
        assert_eq!(registry.next_deposit_idx(), Ok(3));
    }

    #[test]
    fn next_deposit_idx_sparse_keys_returns_max_plus_one() {
        let mut registry = test_empty_registry();
        const MAX_IDX: DepositIdx = 9;
        let min_idx = rand::random::<DepositIdx>() % MAX_IDX;
        insert_deposit_with_graphs(&mut registry, min_idx);
        insert_deposit_with_graphs(&mut registry, MAX_IDX);

        assert_eq!(registry.next_deposit_idx(), Ok(MAX_IDX + 1));
    }

    #[test]
    fn next_deposit_idx_overflow_errors() {
        let mut registry = test_empty_registry();
        insert_deposit_with_graphs(&mut registry, DepositIdx::MAX);

        assert_eq!(
            registry.next_deposit_idx(),
            Err(RegistryInsertError::DepositIdxExhausted(DepositIdx::MAX))
        );
    }

    #[test]
    fn contains_id_true_for_existing() {
        let registry = test_populated_registry(1);

        assert!(registry.contains_id(&SMId::Deposit(0)));
        assert!(registry.contains_id(&SMId::Graph(GraphIdx {
            deposit: 0,
            operator: 1,
        })));
    }

    #[test]
    fn contains_id_false_for_missing() {
        let registry = test_populated_registry(1);

        assert!(!registry.contains_id(&SMId::Deposit(99)));
        assert!(!registry.contains_id(&SMId::Graph(GraphIdx {
            deposit: 99,
            operator: 0,
        })));
    }

    #[test]
    fn get_all_ids_both_types() {
        let registry = test_populated_registry(1);
        let ids = registry.get_all_ids();

        // 1 deposit + N_TEST_OPERATORS graphs (test_populated_registry does not pre-bootstrap
        // stake SMs — tests that exercise stake-gated logic compose those explicitly).
        assert_eq!(ids.len(), 1 + N_TEST_OPERATORS);

        let has_deposit = ids.iter().any(|id| matches!(id, SMId::Deposit(0)));
        let graph_count = ids.iter().filter(|id| matches!(id, SMId::Graph(_))).count();

        assert!(has_deposit);
        assert_eq!(graph_count, N_TEST_OPERATORS);
    }

    // ===== lookup_operator tests =====

    #[test]
    fn lookup_operator_pov() {
        let registry = test_populated_registry(1);
        let id = SMId::Deposit(0);

        let op_idx = registry.lookup_operator(&id, &OperatorKey::Pov);
        assert_eq!(op_idx, Some(TEST_POV_IDX));
    }

    #[test]
    fn lookup_operator_peer_known() {
        let registry = test_populated_registry(1);
        let id = SMId::Deposit(0);

        // Get the P2P key of operator 1 from the operator table used to construct the SM
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let p2p_key = table.idx_to_p2p_key(&1).unwrap().clone();

        let op_idx = registry.lookup_operator(&id, &OperatorKey::Peer(&p2p_key));
        assert_eq!(op_idx, Some(1));
    }

    #[test]
    fn lookup_operator_peer_unknown() {
        let registry = test_populated_registry(1);
        let id = SMId::Deposit(0);

        // A P2P key that doesn't belong to any operator
        let unknown_key = P2POperatorPubKey::from(vec![0xFFu8; 33]);
        let op_idx = registry.lookup_operator(&id, &OperatorKey::Peer(&unknown_key));
        assert!(op_idx.is_none());
    }

    #[test]
    fn lookup_operator_missing_sm() {
        let registry = test_populated_registry(1);
        let id = SMId::Deposit(99);

        let op_idx = registry.lookup_operator(&id, &OperatorKey::Pov);
        assert!(op_idx.is_none());
    }

    // ===== cross-SM context tests =====

    #[test]
    fn graph_cross_sm_context_includes_owner_unstaking_preimage() {
        let mut registry = test_populated_registry(1);
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let graph_idx = GraphIdx {
            deposit: 0,
            operator: 1,
        };
        let preimage = [0x42; 32];

        registry
            .insert_stake(preimage_revealed_stake_sm(
                graph_idx.operator,
                table,
                preimage,
            ))
            .unwrap();

        bind_graph_stake(&mut registry, graph_idx, preimage);
        let context = registry.resolve_cross_sm_context(&SMId::Graph(graph_idx));
        assert_eq!(context.unstaking_preimage(), Some(preimage));
    }

    #[test]
    fn graph_cross_sm_context_does_not_use_different_operator_preimage() {
        let mut registry = test_populated_registry(1);
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let graph_idx = GraphIdx {
            deposit: 0,
            operator: 1,
        };

        registry
            .insert_stake(preimage_revealed_stake_sm(2, table, [0x24; 32]))
            .unwrap();

        let context = registry.resolve_cross_sm_context(&SMId::Graph(graph_idx));
        assert_eq!(context.unstaking_preimage(), None);
    }

    // ===== process_event error tests =====

    #[test]
    fn process_event_sm_not_found() {
        let mut registry = test_populated_registry(1);
        let missing_id = SMId::Deposit(99);
        let event = SMEvent::Deposit(Box::new(DepositEvent::NewBlock(DepositNewBlock {
            block_height: 200,
        })));

        let result = registry.process_event(&missing_id, event);
        assert!(matches!(result, Err(ProcessError::SMNotFound(_))));
    }

    #[test]
    fn process_event_type_mismatch() {
        let mut registry = test_populated_registry(1);

        // Send a graph event to a deposit SM ID → InvalidInvocation
        let deposit_id = SMId::Deposit(0);
        let graph_event = SMEvent::Graph(Box::new(GraphEvent::NewBlock(GraphNewBlock {
            block_height: 200,
        })));

        let result = registry.process_event(&deposit_id, graph_event);
        assert!(matches!(result, Err(ProcessError::InvalidInvocation(_, _))));
    }

    #[test]
    fn inapplicable_nag_received_maps_to_ignored_outcome() {
        let mut registry = test_populated_registry(1);
        let deposit_id = SMId::Deposit(0);
        let event = SMEvent::Deposit(Box::new(DepositEvent::NagReceived(NagReceivedEvent {
            payload: NagRequestPayload::DepositNonce { deposit_idx: 0 },
            sender_operator_idx: 1,
        })));

        let result = registry.process_event(&deposit_id, event);

        assert!(matches!(
            result,
            Ok(ProcessOutcome::Ignored {
                id: SMId::Deposit(0),
                event: SMEvent::Deposit(_),
                reason: IgnoredEventReason::Rejected(reason),
            }) if reason.contains("Inapplicable DepositNonce nag")
                && reason.contains("expected state(s): GraphGenerated | DepositNoncesCollected")
                && reason.contains("payload=NagRequestPayload::DepositNonce")
        ));
    }

    #[test]
    fn process_event_appends_graph_post_stf_duties_from_cross_sm_context() {
        let mut registry = test_populated_registry(1);
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let graph_idx = GraphIdx {
            deposit: 0,
            operator: 1,
        };
        let preimage = [0x42; 32];

        registry
            .insert_stake(preimage_revealed_stake_sm(
                graph_idx.operator,
                table,
                preimage,
            ))
            .unwrap();
        set_graph_claimed_with_unstaking_image(&mut registry, graph_idx, preimage);

        let outcome = registry
            .process_event(
                &SMId::Graph(graph_idx),
                GraphEvent::NewBlock(GraphNewBlock {
                    block_height: INITIAL_BLOCK_HEIGHT + 1,
                })
                .into(),
            )
            .unwrap();

        let ProcessOutcome::Applied(output) = outcome else {
            panic!("expected applied outcome, got {outcome:?}");
        };
        assert!(
            output.duties.iter().any(|duty| {
                matches!(
                    duty,
                    UnifiedDuty::Graph(GraphDuty::PublishUnstakingBurn {
                        graph_idx: duty_graph_idx,
                        unstaking_preimage,
                        ..
                    }) if *duty_graph_idx == graph_idx && *unstaking_preimage == preimage
                )
            }),
            "expected PublishUnstakingBurn duty, got {:?}",
            output.duties
        );
    }

    #[test]
    fn sm_error_duplicate_maps_to_ignored_outcome() {
        let id = SMId::Deposit(7);
        let event = SMEvent::Deposit(Box::new(DepositEvent::NewBlock(DepositNewBlock {
            block_height: 200,
        })));

        let result = process_result_from_sm_error(
            &id,
            event,
            BridgeSMError::Duplicate {
                state: Box::new("state".to_string()),
                event: Box::new("event".to_string()),
            },
        );

        assert!(matches!(
            result,
            Ok(ProcessOutcome::Ignored {
                id: SMId::Deposit(7),
                event: SMEvent::Deposit(_),
                reason: IgnoredEventReason::Duplicate,
            })
        ));
    }

    #[test]
    fn sm_error_rejected_maps_to_ignored_outcome() {
        let id = SMId::Deposit(8);
        let event = SMEvent::Deposit(Box::new(DepositEvent::NewBlock(DepositNewBlock {
            block_height: 210,
        })));
        let reason = "stale event".to_string();

        let result = process_result_from_sm_error(
            &id,
            event,
            BridgeSMError::Rejected {
                state: Box::new("state".to_string()),
                reason: reason.clone(),
                event: Box::new("event".to_string()),
            },
        );

        assert!(matches!(
            result,
            Ok(ProcessOutcome::Ignored {
                id: SMId::Deposit(8),
                event: SMEvent::Deposit(_),
                reason: IgnoredEventReason::Rejected(reject_reason),
            }) if reject_reason == reason
        ));
    }

    #[test]
    fn sm_error_invalid_event_maps_to_fatal_process_error() {
        let id = SMId::Deposit(9);
        let event = SMEvent::Deposit(Box::new(DepositEvent::NewBlock(DepositNewBlock {
            block_height: 220,
        })));
        let reason = "invalid transition".to_string();

        let state_str = "state".to_string();
        let result = process_result_from_sm_error(
            &id,
            event.clone(),
            BridgeSMError::InvalidEvent {
                state: Box::new(state_str.clone()),
                event: Box::new("event".to_string()),
                reason: Some(reason.clone()),
            },
        );

        assert!(matches!(
            result,
            Err(ProcessError::InvariantViolation(dep_id, dep_event, state, err_reason))
                if err_reason == reason && state == state_str && *dep_id == id && dep_event == event
        ));
    }

    fn preimage_revealed_stake_sm(
        operator_idx: OperatorIdx,
        operator_table: OperatorTable,
        preimage: [u8; 32],
    ) -> StakeSM {
        let sm = make_confirmed_stake_sm(operator_idx, operator_table, generate_txid());
        let context = sm.context;
        let StakeState::Confirmed {
            stake_data,
            summary,
            signatures,
            ..
        } = sm.state
        else {
            unreachable!("test helper constructs Confirmed state");
        };

        StakeSM {
            context,
            state: StakeState::PreimageRevealed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                stake_data,
                summary,
                preimage,
                unstaking_intent_block_height: INITIAL_BLOCK_HEIGHT,
                signatures,
            },
        }
    }

    fn bind_graph_stake(registry: &mut SMRegistry, graph_idx: GraphIdx, preimage: [u8; 32]) {
        let graph = registry.graphs.get_mut(&graph_idx).unwrap();
        let stake = registry.stakes.get(&graph.context.stake_key()).unwrap();
        graph.context.stake_outpoint =
            OutPoint::new(stake.state().stake_txid().unwrap(), StakeTx::STAKE_VOUT);
        graph.context.unstaking_image = sha256::Hash::hash(&preimage);
    }

    fn set_graph_claimed_with_unstaking_image(
        registry: &mut SMRegistry,
        graph_idx: GraphIdx,
        preimage: [u8; 32],
    ) {
        bind_graph_stake(registry, graph_idx, preimage);
        let cfg = registry.cfg.graph.clone();
        let graph = registry
            .graphs
            .get_mut(&graph_idx)
            .expect("test registry must contain graph");
        graph.context.unstaking_image = sha256::Hash::hash(&preimage);

        let graph_data = DepositParams {
            game_index: NonZero::new(graph_idx.deposit + 1).expect("deposit index + 1 is non-zero"),
            claim_funds: OutPoint::default(),
            deposit_outpoint: graph.context.deposit_outpoint(),
            adaptor_pubkeys: (0..N_TEST_OPERATORS - 1)
                .map(|_| generate_xonly_pubkey())
                .collect(),
            fault_pubkeys: (0..N_TEST_OPERATORS - 1)
                .map(|_| generate_xonly_pubkey())
                .collect(),
        };
        let graph_summary = generate_game_graph(&cfg, graph.context(), &graph_data).summarize();

        graph.state = GraphState::Claimed {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            graph_data,
            graph_summary,
            signatures: Default::default(),
            fulfillment_txid: Some(generate_txid()),
            fulfillment_block_height: Some(INITIAL_BLOCK_HEIGHT),
            claim_block_height: INITIAL_BLOCK_HEIGHT,
            stake_spent: None,
            payout_connector_spent: None,
        };
    }

    fn test_covenant(table: &OperatorTable) -> CovenantId {
        CovenantId::from_operator_table(table, INITIAL_BLOCK_HEIGHT).unwrap()
    }

    #[test]
    fn historical_graph_retains_preimage_after_unstaking_without_successor_fallback() {
        let mut registry = test_populated_registry(1);
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let graph_idx = GraphIdx {
            deposit: 0,
            operator: TEST_POV_IDX,
        };
        let preimage = [0x42; 32];
        let historical = preimage_revealed_stake_sm(TEST_POV_IDX, table.clone(), preimage);
        let historical_key = historical.context().stake_key();
        // Matching images must not allow a successor to substitute for a missing historical stake.
        let mut successor = preimage_revealed_stake_sm(TEST_POV_IDX, table.clone(), preimage);
        successor.context = StakeSMCtx::new(TEST_POV_IDX, table, INITIAL_BLOCK_HEIGHT + 100);
        registry.insert_stake(historical).unwrap();
        registry.insert_stake(successor).unwrap();
        bind_graph_stake(&mut registry, graph_idx, preimage);
        let original = registry.graphs[&graph_idx].context.clone();
        let id = SMId::Graph(graph_idx);
        assert_eq!(
            registry.resolve_cross_sm_context(&id).unstaking_preimage(),
            Some(preimage)
        );

        let historical = registry.stakes.get_mut(&historical_key).unwrap();
        let StakeState::PreimageRevealed {
            summary,
            preimage: revealed_preimage,
            ..
        } = historical.state()
        else {
            panic!("historical stake must have revealed its preimage");
        };
        historical.state = StakeState::Unstaked {
            preimage: *revealed_preimage,
            unstaking_txid: summary.unstaking,
        };
        assert_eq!(
            registry.resolve_stake_outpoint(&original.stake_outpoint),
            None
        );
        assert_eq!(
            registry.resolve_cross_sm_context(&id).unstaking_preimage(),
            Some(preimage)
        );

        registry
            .graphs
            .get_mut(&graph_idx)
            .unwrap()
            .context
            .unstaking_image = sha256::Hash::hash(&[0x24; 32]);
        assert_eq!(
            registry.resolve_cross_sm_context(&id).unstaking_preimage(),
            None
        );
        registry.graphs.get_mut(&graph_idx).unwrap().context = original;
        registry.stakes.remove(&historical_key);
        assert_eq!(
            registry.resolve_cross_sm_context(&id).unstaking_preimage(),
            None
        );
    }

    #[test]
    fn readiness_uses_only_requested_covenants_complete_membership() {
        let mut registry = test_empty_registry();
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let historical = test_covenant(&table);
        let successor = CovenantId {
            activation_height: INITIAL_BLOCK_HEIGHT + 100,
            ..historical
        };
        for operator in table.operator_idxs() {
            insert_confirmed_stake(&mut registry, operator, table.clone(), generate_txid());
        }
        let historical_inputs = registry
            .active_operator_snapshot(historical, &table)
            .unwrap()
            .stake_inputs;
        assert!(matches!(
            registry.active_operator_snapshot(successor, &table),
            Err(SnapshotError::MissingStakeSM(_))
        ));
        for operator in table.operator_idxs() {
            let (sm, _) = StakeSM::new(
                StakeSMCtx::new(operator, table.clone(), successor.activation_height),
                INITIAL_BLOCK_HEIGHT,
            );
            registry.insert_stake(sm).unwrap();
        }
        assert!(matches!(
            registry.active_operator_snapshot(successor, &table),
            Err(SnapshotError::StakeUnavailable(_))
        ));
        assert_eq!(
            registry
                .active_operator_snapshot(historical, &table)
                .unwrap()
                .stake_inputs,
            historical_inputs
        );
        for operator in table.operator_idxs() {
            let mut sm = make_confirmed_stake_sm(operator, table.clone(), generate_txid());
            sm.context = StakeSMCtx::new(operator, table.clone(), successor.activation_height);
            registry.stakes.insert(sm.context().stake_key(), sm);
        }
        let snapshot = registry
            .active_operator_snapshot(successor, &table)
            .unwrap();
        assert_eq!(snapshot.covenant, successor);
        assert_eq!(snapshot.operator_table, table);
        for operator in table.operator_idxs() {
            assert_ne!(
                snapshot.stake_inputs[&operator],
                historical_inputs[&operator]
            );
        }
    }

    #[test]
    fn readiness_rejects_equal_aggregate_with_different_p2p_membership() {
        let mut registry = test_empty_registry();
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let covenant = test_covenant(&table);
        for operator in table.operator_idxs() {
            insert_confirmed_stake(&mut registry, operator, table.clone(), generate_txid());
        }
        let entries = table
            .operator_idxs()
            .into_iter()
            .map(|idx| {
                (
                    idx,
                    table
                        .idx_to_p2p_key(&((idx + 1) % N_TEST_OPERATORS as u32))
                        .unwrap()
                        .clone(),
                    table.idx_to_btc_key(&idx).unwrap(),
                )
            })
            .collect();
        let changed = OperatorTable::new(entries, |(idx, _, _)| *idx == TEST_POV_IDX).unwrap();
        assert_eq!(test_covenant(&changed), covenant);
        assert!(
            matches!(registry.active_operator_snapshot(covenant, &changed), Err(SnapshotError::CovenantMembershipMismatch(id)) if id == covenant)
        );
    }

    // ===== Stake SM gating / snapshot tests =====

    #[test]
    fn is_operator_active_tracks_confirmed_state() {
        let mut registry = test_empty_registry();
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);

        assert!(!registry.is_operator_active_for_new_deposits(&StakeKey {
            covenant: test_covenant(&table),
            operator: TEST_POV_IDX
        }));

        insert_confirmed_stake(&mut registry, TEST_POV_IDX, table.clone(), generate_txid());

        assert!(registry.is_operator_active_for_new_deposits(&StakeKey {
            covenant: test_covenant(&table),
            operator: TEST_POV_IDX
        }));
    }

    #[test]
    fn active_operator_snapshot_rejects_partially_confirmed_membership() {
        let mut registry = test_empty_registry();
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);

        // Confirm POV and a second operator; leave the third in `Created`.
        let op_idxs: Vec<_> = table.operator_idxs().into_iter().collect();
        let non_pov_confirmed = *op_idxs.iter().find(|idx| **idx != TEST_POV_IDX).unwrap();
        let remaining = *op_idxs
            .iter()
            .find(|idx| **idx != TEST_POV_IDX && **idx != non_pov_confirmed)
            .unwrap();

        insert_confirmed_stake(&mut registry, TEST_POV_IDX, table.clone(), generate_txid());
        insert_confirmed_stake(
            &mut registry,
            non_pov_confirmed,
            table.clone(),
            generate_txid(),
        );
        insert_created_stake(&mut registry, remaining, table.clone());

        assert!(
            matches!(registry.active_operator_snapshot(test_covenant(&table), &table),
            Err(SnapshotError::StakeUnavailable(key)) if key.operator == remaining)
        );
    }

    #[test]
    fn active_operator_snapshot_errors_when_pov_is_not_active() {
        let mut registry = test_empty_registry();
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);

        // Confirm only a non-POV operator; POV and one other stay in `Created`.
        let op_idxs: Vec<_> = table.operator_idxs().into_iter().collect();
        let non_pov = *op_idxs.iter().find(|idx| **idx != TEST_POV_IDX).unwrap();
        insert_confirmed_stake(&mut registry, non_pov, table.clone(), generate_txid());

        // Other operators need `Created` SSMs so the snapshot sees them at all.
        for op_idx in op_idxs.iter().filter(|idx| **idx != non_pov) {
            insert_created_stake(&mut registry, *op_idx, table.clone());
        }

        let err = registry
            .active_operator_snapshot(test_covenant(&table), &table)
            .expect_err("snapshot should error when POV is not confirmed");
        assert!(
            matches!(err, SnapshotError::StakeUnavailable(key) if key.operator == TEST_POV_IDX)
        );
    }

    #[test]
    fn active_operator_snapshot_errors_when_operator_missing_stake_sm() {
        let registry = test_empty_registry();
        // Registry has no stake SMs at all; the operator table still has them.
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);

        let err = registry
            .active_operator_snapshot(test_covenant(&table), &table)
            .expect_err("snapshot should error when a stake SM is missing from the registry");
        assert!(matches!(err, SnapshotError::MissingStakeSM(_)));
    }

    #[test]
    fn stake_inputs_use_stake_vout_from_confirmed_txid() {
        let mut registry = test_empty_registry();
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let stake_txid = generate_txid();
        for op_idx in table.operator_idxs() {
            let tx_for_op = if op_idx == TEST_POV_IDX {
                stake_txid
            } else {
                generate_txid()
            };
            insert_confirmed_stake(&mut registry, op_idx, table.clone(), tx_for_op);
        }

        let snapshot = registry
            .active_operator_snapshot(test_covenant(&table), &table)
            .unwrap();
        let pov_input = snapshot.stake_inputs.get(&TEST_POV_IDX).unwrap();
        assert_eq!(pov_input.txid, stake_txid);
        assert_eq!(pov_input.vout, StakeTx::STAKE_VOUT);
    }
}

#[cfg(test)]
mod covenant_tests {
    use strata_bridge_primitives::operator_table::PublicOperatorTable;
    use strata_bridge_sm::stake::{
        context::StakeSMCtx,
        events::{NagTickEvent, NewBlockEvent},
    };

    use super::*;
    use crate::testing::{
        N_TEST_OPERATORS, TEST_POV_IDX, test_empty_registry, test_operator_table,
    };

    pub(super) fn stakes_at_two_heights() -> (StakeSM, StakeSM) {
        let table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let (first, _) = StakeSM::new(StakeSMCtx::new(TEST_POV_IDX, table.clone(), 100), 101);
        let (second, _) = StakeSM::new(StakeSMCtx::new(TEST_POV_IDX, table, 200), 101);
        (first, second)
    }

    #[test]
    fn same_owner_and_aggregate_at_different_heights_progress_independently() {
        let (first, second) = stakes_at_two_heights();
        let first_key = first.context().stake_key();
        let second_key = second.context().stake_key();
        assert_eq!(
            first_key.covenant.aggregate_pubkey,
            second_key.covenant.aggregate_pubkey
        );
        let mut registry = test_empty_registry();
        registry.insert_stake(first.clone()).unwrap();
        assert_eq!(
            registry.resolve_legacy_stake_key(TEST_POV_IDX),
            Some(first_key)
        );
        registry.insert_stake(second.clone()).unwrap();
        assert_eq!(registry.resolve_legacy_stake_key(TEST_POV_IDX), None);
        assert!(
            matches!(registry.insert_stake(first), Err(RegistryInsertError::StakeAlreadyExists(k)) if k == first_key)
        );
        registry
            .process_event(
                &SMId::Stake(first_key),
                StakeEvent::NewBlock(NewBlockEvent { block_height: 102 }).into(),
            )
            .unwrap();
        assert_eq!(
            registry
                .get_stake(&first_key)
                .unwrap()
                .state()
                .last_processed_block_height(),
            Some(102)
        );
        assert_eq!(registry.get_stake(&second_key), Some(&second));
        let mut absent = second_key;
        absent.covenant.activation_height = 300;
        assert!(registry.get_stake(&absent).is_none());
    }

    #[test]
    fn nag_duties_retain_their_stake_key() {
        let (first, second) = stakes_at_two_heights();
        let keys = [first.context().stake_key(), second.context().stake_key()];
        let mut registry = test_empty_registry();
        registry.insert_stake(first).unwrap();
        registry.insert_stake(second).unwrap();
        for expected in keys {
            let output = registry
                .process_event(
                    &SMId::Stake(expected),
                    StakeEvent::NagTick(NagTickEvent).into(),
                )
                .unwrap();
            let ProcessOutcome::Applied(output) = output else {
                panic!("nag tick must apply");
            };
            assert_eq!(output.duties.len(), 1);
            let UnifiedDuty::Stake { stake_key, .. } = &output.duties[0] else {
                panic!("stake duty expected");
            };
            assert_eq!(*stake_key, expected);
        }
    }

    #[test]
    fn equal_identity_with_different_indexed_membership_is_rejected() {
        let (first, _) = stakes_at_two_heights();
        let key = first.context().stake_key();
        let table = first.context().operator_table();
        let entries = table
            .operator_idxs()
            .into_iter()
            .map(|idx| {
                (
                    idx + 10,
                    table.idx_to_p2p_key(&idx).unwrap().clone(),
                    table.idx_to_btc_key(&idx).unwrap(),
                )
            })
            .collect();
        let remapped = PublicOperatorTable::from_entries(entries).unwrap();
        let ctx = StakeSMCtx::new(
            key.operator + 10,
            remapped.with_pov(table.pov_idx() + 10).unwrap(),
            key.covenant.activation_height,
        );
        let (other, _) = StakeSM::new(ctx, 101);
        let mut registry = test_empty_registry();
        registry.insert_stake(first).unwrap();
        assert!(matches!(
            registry.insert_stake(other),
            Err(RegistryInsertError::CovenantMembershipMismatch(_))
        ));
    }
}

#[cfg(test)]
mod operator_set_tests {
    use std::collections::BTreeSet;

    use bitcoin::{Txid, hashes::Hash};
    use strata_bridge_sm::{
        operator_set::{
            ConfirmedExit, ExitKind, OperatorSetError, OperatorSetEvent, OperatorSetSM,
        },
        stake::{context::StakeSMCtx, machine::StakeSM},
    };

    use super::{IgnoredEventReason, ProcessOutcome, RegistryInsertError};
    use crate::{
        applicator::Applicator,
        errors::ProcessError,
        events_mux::UnifiedEvent,
        events_router,
        sm_types::SMId,
        testing::{test_empty_registry, test_operator_set_sm},
    };

    fn exit_block(operator_idx: u32) -> OperatorSetEvent {
        OperatorSetEvent::NewBlock {
            block_height: 101,
            exits: vec![ConfirmedExit {
                operator_idx,
                txid: Txid::from_byte_array([7; 32]),
                tx_index: 3,
                kind: ExitKind::Slash,
            }],
        }
    }

    #[test]
    fn singleton_registration_is_addressable_and_cannot_overwrite_existing_history() {
        let mut registry = test_empty_registry();
        let sm = test_operator_set_sm();
        registry.insert_operator_set(sm.clone()).unwrap();
        assert_eq!(
            registry.get_all_ids(),
            vec![SMId::OperatorSet],
            "The singleton membership machine must appear in registry-wide enumeration"
        );
        assert!(registry.contains_id(&SMId::OperatorSet));
        assert_eq!(
            registry.insert_operator_set(sm.clone()),
            Err(RegistryInsertError::OperatorSetAlreadyExists),
            "A second insertion must be rejected instead of overwriting membership history"
        );
        assert_eq!(
            registry.get_operator_set(),
            Some(&sm),
            "Rejecting a duplicate insertion must preserve the original membership machine"
        );
        assert!(events_router::route(&UnifiedEvent::NagTick, &registry).is_empty());
        assert!(events_router::route(&UnifiedEvent::RetryTick, &registry).is_empty());
    }

    #[test]
    fn observer_and_participant_derive_identical_membership_and_initialization_intent() {
        let mut observer = test_empty_registry();
        let mut participant = test_empty_registry();
        let membership = test_operator_set_sm();
        let table = membership
            .current_operator_table()
            .unwrap()
            .with_pov(0)
            .unwrap();
        for operator_idx in table.operator_idxs() {
            let (stake, _) = StakeSM::new(StakeSMCtx::new(operator_idx, table.clone(), 100), 100);
            participant.insert_stake(stake).unwrap();
        }
        observer.insert_operator_set(membership.clone()).unwrap();
        participant.insert_operator_set(membership).unwrap();
        let mut outputs = Vec::new();
        for registry in [&mut observer, &mut participant] {
            let ProcessOutcome::Applied(output) = registry
                .process_event(&SMId::OperatorSet, exit_block(1).into())
                .unwrap()
            else {
                panic!("membership transition must apply")
            };
            assert!(output.duties.is_empty());
            outputs.push(output.signals);
            let sm = registry.get_operator_set().unwrap();
            assert_eq!(
                sm.current_covenant().activation_height,
                100,
                "Automatic exits must preserve the admin boundary regardless of local stake availability"
            );
            assert_eq!(
                sm.current_operator_table().unwrap().operator_idxs(),
                BTreeSet::from([0]),
                "Observers and participants must both remove the exited index from public membership"
            );
        }
        assert_eq!(
            outputs[0], outputs[1],
            "Local stake availability must not change membership initialization intent"
        );
        assert_eq!(
            observer.get_operator_set(),
            participant.get_operator_set(),
            "Observers and participants must derive identical complete membership state"
        );
        assert_eq!(
            observer.num_stakes(),
            0,
            "An observer must track membership without any local stake machines"
        );
        assert_eq!(
            participant.num_stakes(),
            2,
            "Membership processing must not remove or create participant stake machines"
        );
    }

    #[test]
    fn restored_membership_rejects_duplicate_block_without_another_signal() {
        let mut registry = test_empty_registry();
        registry
            .insert_operator_set(test_operator_set_sm())
            .unwrap();
        registry
            .process_event(&SMId::OperatorSet, exit_block(1).into())
            .unwrap();
        let sm = registry.get_operator_set().unwrap();
        let restored: OperatorSetSM =
            postcard::from_bytes(&postcard::to_allocvec(sm).unwrap()).unwrap();
        let signals = restored.initialization_signals().unwrap();
        let mut recovered_registry = test_empty_registry();
        recovered_registry.insert_operator_set(restored).unwrap();
        assert!(matches!(
            recovered_registry
                .process_event(&SMId::OperatorSet, exit_block(1).into())
                .unwrap(),
            ProcessOutcome::Ignored {
                reason: IgnoredEventReason::Duplicate,
                ..
            }
        ));
        assert_eq!(
            recovered_registry.get_operator_set(),
            registry.get_operator_set(),
            "Ignoring a duplicate block must preserve the restored membership state"
        );
        assert_eq!(
            recovered_registry
                .get_operator_set()
                .unwrap()
                .initialization_signals()
                .unwrap(),
            signals,
            "Ignoring a duplicate block must preserve the finalized covenant initialization intent"
        );
    }

    #[test]
    fn ordinary_block_is_tracked_for_persistence_without_staking_duties() {
        let mut registry = test_empty_registry();
        registry
            .insert_operator_set(test_operator_set_sm())
            .unwrap();
        let mut applicator = Applicator::new(&mut registry);
        applicator
            .apply_batch([(
                SMId::OperatorSet,
                OperatorSetEvent::NewBlock {
                    block_height: 101,
                    exits: vec![],
                }
                .into(),
            )])
            .unwrap();
        let (duties, tracker) = applicator.finish();
        assert!(duties.is_empty());
        assert_eq!(
            tracker.into_batches(),
            vec![BTreeSet::from([SMId::OperatorSet])],
            "Advancing the membership processing height must mark the singleton for persistence"
        );
    }

    #[test]
    fn impossible_exit_sequence_is_fatal_and_leaves_registry_membership_unchanged() {
        let mut registry = test_empty_registry();
        let sm = test_operator_set_sm();
        registry.insert_operator_set(sm.clone()).unwrap();
        let OperatorSetEvent::NewBlock {
            block_height,
            mut exits,
        } = exit_block(1)
        else {
            unreachable!()
        };
        exits.push(ConfirmedExit {
            operator_idx: 0,
            txid: Txid::from_byte_array([8; 32]),
            tx_index: 4,
            ..exits[0].clone()
        });
        let event = OperatorSetEvent::NewBlock {
            block_height,
            exits,
        };
        assert!(matches!(
            registry.process_event(&SMId::OperatorSet, event.into()),
            Err(ProcessError::OperatorSet(OperatorSetError::EmptyMembership))
        ));
        assert_eq!(
            registry.get_operator_set(),
            Some(&sm),
            "Rejecting a last-member exit must roll back the earlier exit in the same block"
        );
    }
}
