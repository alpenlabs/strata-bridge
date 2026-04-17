//! The main event loop that wires all pipeline stages together:
//! `EventsMux` → classify → `Applicator::apply_batch` → persist → dispatch.

use std::collections::BTreeSet;

use strata_bridge_primitives::{operator_table::OperatorTable, types::BitcoinBlockHeight};
use strata_bridge_sm::stake::{context::StakeSMCtx, machine::StakeSM};
use tracing::{info, trace};

use crate::{
    applicator::Applicator,
    duty_dispatcher::DutyDispatcher,
    errors::{PipelineError, ProcessError},
    events_classifier::{offchain, onchain},
    events_mux::{EventsMux, UnifiedEvent},
    events_router,
    persister::Persister,
    sm_registry::SMRegistry,
    sm_types::{SMId, UnifiedDuty},
};

/// The main pipeline that drives the orchestrator.
///
/// Continuously pulls events from the multiplexer, classifies and routes them to state machines,
/// processes them through the [`Applicator`], persists state changes, and dispatches duties to
/// executors.
#[expect(missing_debug_implementations)]
pub struct Pipeline {
    event_mux: EventsMux,
    registry: SMRegistry,
    persister: Persister,
    dispatcher: DutyDispatcher,
}

impl Pipeline {
    /// Creates a new pipeline with all required components.
    pub const fn new(
        event_mux: EventsMux,
        registry: SMRegistry,
        persister: Persister,
        dispatcher: DutyDispatcher,
    ) -> Self {
        Self {
            event_mux,
            registry,
            persister,
            dispatcher,
        }
    }

    /// Runs the main event loop until shutdown.
    ///
    /// On shutdown, sends the signal through the oneshot channel and returns.
    ///
    /// The `initial_operator_table` needs to be constructed from a params file or similar source of
    /// truth for now. Eventually, this will be queried from the Operator State Machine in the
    /// registry.
    ///
    /// Before entering the main event loop, this method bootstraps one [`StakeSM`] per operator in
    /// the `initial_operator_table`. Any stake SMs already recovered from the database are
    /// preserved; only missing ones are created. The `start_height` is used as the initial block
    /// height for newly created stake SMs (typically the chain tip or the persisted cursor).
    pub async fn run(
        mut self,
        initial_operator_table: OperatorTable,
        start_height: BitcoinBlockHeight,
    ) -> Result<(), PipelineError> {
        self.bootstrap_stake_sms(&initial_operator_table, start_height)
            .await?;

        loop {
            // Stage 1: Multiplex event streams
            let event = self.event_mux.next().await;
            trace!(?event, "received new event from multiplexer");

            // Handle non-routable events (consume `event` on early exit, rebind otherwise)
            let event = match event {
                UnifiedEvent::Shutdown => {
                    info!("received shutdown signal, breaking out of event loop");
                    return Ok(());
                }

                // Routable events — pass through to the classification stage
                routable => routable,
            };

            // Stage 2+3: Classify and process through Applicator
            let mut applicator = Applicator::new(&mut self.registry);

            match &event {
                UnifiedEvent::Block(block_event) => {
                    onchain::process_block(&mut applicator, &initial_operator_table, block_event)?;
                }

                _ => {
                    // P2P / assignment / ticks: route to SM ids, then classify each
                    trace!(
                        ?event,
                        "classifying event and determining target state machines"
                    );
                    let sm_ids = events_router::route(&event, applicator.registry());
                    let seed_events: Vec<_> = sm_ids
                        .into_iter()
                        .filter_map(|sm_id| {
                            offchain::classify(&sm_id, &event, applicator.registry())
                                .map(|sm_event| (sm_id, sm_event))
                        })
                        .collect();

                    applicator.apply_batch(seed_events)?;
                }
            }

            let (all_duties, tracker) = applicator.finish();

            // Stage 4: Batch persistence
            let batches = tracker.into_batches();
            info!(count=%batches.len(), "persisting updated state machines batches");
            for batch in batches {
                self.persister.persist_batch(batch, &self.registry).await?;
            }

            // Stage 5: Dispatch duties
            for duty in all_duties {
                self.dispatcher.dispatch(duty);
            }
        }
    }

    /// Creates one stake state machine per operator in `operator_table` that does not yet exist in
    /// the registry. Persists the newly created machines and dispatches any constructor duties
    /// (only the POV operator's SSM emits `PublishStakeData`).
    async fn bootstrap_stake_sms(
        &mut self,
        operator_table: &OperatorTable,
        start_height: BitcoinBlockHeight,
    ) -> Result<(), PipelineError> {
        let mut touched: BTreeSet<SMId> = BTreeSet::new();
        let mut duties: Vec<UnifiedDuty> = Vec::new();

        for op_idx in operator_table.operator_idxs() {
            if self.registry.contains_id(&SMId::Stake(op_idx)) {
                continue;
            }

            let ctx = StakeSMCtx::new(op_idx, operator_table.clone());
            let (ssm, initial_duty) = StakeSM::new(ctx, start_height);
            self.registry
                .insert_stake(op_idx, ssm)
                .map_err(ProcessError::from)?;
            touched.insert(SMId::Stake(op_idx));
            info!(%op_idx, %start_height, "bootstrapped stake state machine");

            if let Some(duty) = initial_duty {
                duties.push(duty.into());
            }
        }

        if !touched.is_empty() {
            self.persister
                .persist_batch(touched, &self.registry)
                .await?;
        }
        for duty in duties {
            self.dispatcher.dispatch(duty);
        }

        Ok(())
    }
}
