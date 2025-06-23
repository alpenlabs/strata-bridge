//! Actor-based wrapper around [`ContractSM`] that allows each contract to run in its own task,
//! enabling parallel processing of independent contracts.

use std::{collections::BTreeMap, sync::Arc};

use algebra::req::Req;
use bitcoin::{Transaction, Txid};
use strata_bridge_tx_graph::transactions::covenant_tx::CovenantTx;
use tokio::{sync::mpsc, task::JoinHandle};
use tracing::{debug, error, info, trace, warn};

/// Channel for sending duty responses from contract actors back to the main event loop.
pub type DutyResponseSender =
    mpsc::UnboundedSender<(Txid, Result<Vec<OperatorDuty>, TransitionErr>)>;

use crate::{
    contract_persister::{ContractPersistErr, ContractPersister},
    contract_state_machine::{
        ContractCfg, ContractEvent, ContractSM, ContractState, MachineState, OperatorDuty,
        TransitionErr,
    },
    stake_chain_persister::StakeChainPersister,
};

/// Message types that can be sent to a [`ContractActor`].
#[expect(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ContractActorMessage {
    /// Process a [`ContractEvent`] and return resulting [`OperatorDuty`]s.
    ProcessEvent {
        /// The request containing the event to process.
        req: Option<Req<ContractEvent, Result<Vec<OperatorDuty>, TransitionErr>>>,

        /// Channel to send [`OperatorDuty`]s to (for asynchronous processing).
        duty_response_sender: Option<DutyResponseSender>,

        /// The event to process (for async case).
        event: Option<ContractEvent>,
    },

    /// Gets the current [`MachineState`] of the contract.
    GetState(Req<(), MachineState>),

    /// Gets the [`ContractCfg`] of the contract.
    GetConfig(Req<(), ContractCfg>),

    /// Checks if the contract handles a specific bitcoin [`Transaction`].
    TransactionFilter(Req<Transaction, bool>),

    /// Gets claim transaction IDs for this contract.
    GetClaimTxids(Req<(), Vec<Txid>>),

    /// Gets the deposit transaction ID.
    GetDepositTxid(Req<(), Txid>),

    /// Gets the deposit request transaction ID.
    GetDepositRequestTxid(Req<(), Txid>),

    /// Gets the withdrawal request transaction ID (if any).
    GetWithdrawalRequestTxid(Req<(), Option<Txid>>),

    /// Gets the withdrawal fulfillment transaction ID (if any).
    GetWithdrawalFulfillmentTxid(Req<(), Option<Txid>>),

    /// Clears the peg-out-graph cache.
    ClearPogCache,

    /// Gracefully shutdowns the actor.
    Shutdown,
}

/// Handles required by the contract actor for state persistence.
#[derive(Debug, Clone)]
pub struct ContractActorStateHandles {
    /// Contract persister for saving contract state.
    pub contract_persister: Arc<ContractPersister>,

    /// Stake chain persister for saving stake chain data.
    pub stake_chain_persister: Arc<StakeChainPersister>,
}

/// Actor wrapper around [`ContractSM`] that runs in its own task.
#[derive(Debug)]
pub struct ContractActor {
    /// Transaction ID of the deposit this contract manages.
    pub deposit_txid: Txid,

    /// Channel for sending messages to the actor.
    event_sender: mpsc::UnboundedSender<ContractActorMessage>,

    /// Handle to the actor task.
    handle: JoinHandle<()>,
}

impl ContractActor {
    /// Spawns a new contract actor with the given [`ContractCfg`] and initial [`MachineState`].
    pub fn spawn(
        cfg: ContractCfg,
        initial_state: MachineState,
        state_handles: ContractActorStateHandles,
    ) -> Self {
        let (event_sender, mut event_receiver) = mpsc::unbounded_channel();
        let deposit_txid = cfg.deposit_tx.compute_txid();

        let handle = tokio::spawn(async move {
            let mut csm = ContractSM::restore(cfg.clone(), initial_state);

            info!(%deposit_txid, "contract actor started");

            while let Some(message) = event_receiver.recv().await {
                match message {
                    ContractActorMessage::ProcessEvent {
                        req,
                        duty_response_sender,
                        event,
                    } => {
                        if let Some(req) = req {
                            // Synchronous processing with direct response
                            let (event, response_sender) = req.into_input_output();
                            debug!(%deposit_txid, "processing contract event (sync)");
                            trace!(%deposit_txid, ?event, "processing contract event (sync)");

                            let result = csm.process_contract_event(event);

                            // Persist state after successful processing
                            if result.is_ok() {
                                if let Err(e) =
                                    Self::persist_state(&csm, &state_handles.contract_persister)
                                        .await
                                {
                                    error!(%deposit_txid, %e, "failed to persist CSM state after event processing");
                                    // Don't fail the event processing due to persistence errors
                                    // The state is still updated in memory
                                    warn!(%deposit_txid, "continuing with in-memory state despite persistence failure");
                                }
                            }

                            let _ = response_sender.send(result);
                        } else if let Some(event) = event {
                            // Asynchronous processing with duty response channel
                            debug!(%deposit_txid, "processing contract event (async)");
                            trace!(%deposit_txid, ?event, "processing contract event (sync)");

                            let result = csm.process_contract_event(event);

                            // Persist state after successful processing
                            if result.is_ok() {
                                if let Err(e) =
                                    Self::persist_state(&csm, &state_handles.contract_persister)
                                        .await
                                {
                                    error!(%deposit_txid, %e, "failed to persist CSM state after event processing");
                                    // Don't fail the event processing due to persistence errors
                                    // The state is still updated in memory
                                    warn!(%deposit_txid, "continuing with in-memory state despite persistence failure");
                                }
                            }

                            // Send response via duty channel for async processing
                            if let Some(duty_sender) = duty_response_sender {
                                let _ = duty_sender.send((deposit_txid, result));
                            }
                        } else {
                            error!(%deposit_txid, "processEvent message missing both req and event");
                        }
                    }
                    ContractActorMessage::GetState(req) => {
                        req.resolve(csm.state().clone());
                    }
                    ContractActorMessage::GetConfig(req) => {
                        req.resolve(csm.cfg().clone());
                    }
                    ContractActorMessage::TransactionFilter(req) => {
                        req.dispatch(|tx| csm.transaction_filter(&tx));
                    }
                    ContractActorMessage::GetClaimTxids(req) => {
                        req.resolve(csm.claim_txids());
                    }
                    ContractActorMessage::GetDepositTxid(req) => {
                        req.resolve(csm.deposit_txid());
                    }
                    ContractActorMessage::GetDepositRequestTxid(req) => {
                        req.resolve(csm.deposit_request_txid());
                    }
                    ContractActorMessage::GetWithdrawalRequestTxid(req) => {
                        req.resolve(csm.withdrawal_request_txid());
                    }
                    ContractActorMessage::GetWithdrawalFulfillmentTxid(req) => {
                        req.resolve(csm.withdrawal_fulfillment_txid());
                    }
                    ContractActorMessage::ClearPogCache => {
                        csm.clear_pog_cache();
                        debug!(%deposit_txid, "cleared peg-out-graph cache");
                    }
                    ContractActorMessage::Shutdown => {
                        info!(%deposit_txid, "contract actor shutting down");
                        break;
                    }
                }
            }

            info!(%deposit_txid, "contract actor terminated");
        });

        Self {
            deposit_txid,
            event_sender,
            handle,
        }
    }

    /// Processes a contract event and returns resulting [`OperatorDuty`]s.
    pub async fn process_event(
        &self,
        event: ContractEvent,
    ) -> Result<Vec<OperatorDuty>, TransitionErr> {
        let (req, receiver) = Req::new(event);
        self.event_sender
            .send(ContractActorMessage::ProcessEvent {
                req: Some(req),
                duty_response_sender: None,
                event: None,
            })
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver
            .await
            .map_err(|_| TransitionErr("failed to receive response from CSM actor".to_string()))?
    }

    /// Processes a contract event asynchronously, sending duties to the provided channel.
    pub fn process_event_async(
        &self,
        event: ContractEvent,
        duty_response_sender: DutyResponseSender,
    ) -> Result<(), TransitionErr> {
        self.event_sender
            .send(ContractActorMessage::ProcessEvent {
                req: None,
                duty_response_sender: Some(duty_response_sender),
                event: Some(event),
            })
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        Ok(())
    }

    /// Gets the current [`MachineState`] of the contract.
    pub async fn get_state(&self) -> Result<MachineState, TransitionErr> {
        let (req, receiver) = Req::new(());
        self.event_sender
            .send(ContractActorMessage::GetState(req))
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver
            .await
            .map_err(|_| TransitionErr("failed to receive state from CSM actor".to_string()))
    }

    /// Gets the contract [`ContractCfg`].
    pub async fn get_config(&self) -> Result<ContractCfg, TransitionErr> {
        let (req, receiver) = Req::new(());
        self.event_sender
            .send(ContractActorMessage::GetConfig(req))
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver
            .await
            .map_err(|_| TransitionErr("failed to receive config from CSM actor".to_string()))
    }

    /// Checks if the contract handles a specific transaction.
    pub async fn transaction_filter(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<bool, TransitionErr> {
        let (req, receiver) = Req::new(tx.clone());
        self.event_sender
            .send(ContractActorMessage::TransactionFilter(req))
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver.await.map_err(|_| {
            TransitionErr("failed to receive filter result from CSM actor".to_string())
        })
    }

    /// Gets claim transaction IDs for this contract.
    pub async fn claim_txids(&self) -> Result<Vec<Txid>, TransitionErr> {
        let (req, receiver) = Req::new(());
        self.event_sender
            .send(ContractActorMessage::GetClaimTxids(req))
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver
            .await
            .map_err(|_| TransitionErr("failed to receive claim txids from CSM actor".to_string()))
    }

    /// Gets the deposit request transaction ID.
    pub async fn deposit_request_txid(&self) -> Result<Txid, TransitionErr> {
        let (req, receiver) = Req::new(());
        self.event_sender
            .send(ContractActorMessage::GetDepositRequestTxid(req))
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver.await.map_err(|_| {
            TransitionErr("failed to receive deposit request txid from CSM actor".to_string())
        })
    }

    /// Gets the withdrawal request transaction ID (if any).
    pub async fn withdrawal_request_txid(&self) -> Result<Option<Txid>, TransitionErr> {
        let (req, receiver) = Req::new(());
        self.event_sender
            .send(ContractActorMessage::GetWithdrawalRequestTxid(req))
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver.await.map_err(|_| {
            TransitionErr("failed to receive withdrawal request txid from CSM actor".to_string())
        })
    }

    /// Get the withdrawal fulfillment transaction ID (if any).
    pub async fn withdrawal_fulfillment_txid(&self) -> Result<Option<Txid>, TransitionErr> {
        let (req, receiver) = Req::new(());
        self.event_sender
            .send(ContractActorMessage::GetWithdrawalFulfillmentTxid(req))
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver.await.map_err(|_| {
            TransitionErr(
                "failed to receive withdrawal fulfillment txid from CSM actor".to_string(),
            )
        })
    }

    /// Clears the peg-out-graph cache.
    pub async fn clear_pog_cache(&self) -> Result<(), TransitionErr> {
        self.event_sender
            .send(ContractActorMessage::ClearPogCache)
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;
        Ok(())
    }

    /// Gracefully shutdowns the actor.
    pub async fn shutdown(self) -> Result<(), TransitionErr> {
        let _ = self.event_sender.send(ContractActorMessage::Shutdown);

        // Wait for the actor to finish with a timeout
        let handle = self.handle;
        match tokio::time::timeout(std::time::Duration::from_secs(30), handle).await {
            Ok(result) => {
                result.map_err(|e| TransitionErr(format!("actor task panicked: {e}")))?;
                Ok(())
            }
            Err(_) => {
                warn!(deposit_txid=%self.deposit_txid, "Actor shutdown timed out, aborting");
                // Handle was moved into timeout, so we need to create a new abort mechanism
                // In this case, the timeout already happened, so the task should be dropped
                Err(TransitionErr("actor shutdown timed out".to_string()))
            }
        }
    }

    /// Helper to persist CSM state.
    async fn persist_state(
        csm: &ContractSM,
        persister: &ContractPersister,
    ) -> Result<(), ContractPersistErr> {
        persister
            .commit(
                &csm.deposit_txid(),
                csm.cfg().deposit_idx,
                &csm.cfg().deposit_tx,
                &csm.cfg().operator_table,
                csm.state(),
            )
            .await
    }
}

/// Manager for [`ContractActor`]s that handles lifecycle and batch operations.
#[derive(Debug)]
pub struct ContractActorManager {
    /// Active [`ContractActor`]s indexed by deposit transaction ID.
    actors: BTreeMap<Txid, ContractActor>,

    /// Index from deposit request transaction ID to deposit transaction ID for fast lookup.
    deposit_request_to_deposit: BTreeMap<Txid, Txid>,
}

impl ContractActorManager {
    /// Creates a new empty [`ContractActorManager`].
    pub const fn new() -> Self {
        Self {
            actors: BTreeMap::new(),
            deposit_request_to_deposit: BTreeMap::new(),
        }
    }

    /// Adds a new [`ContractActor`] given a deposit request transaction ID.
    pub fn add_actor(&mut self, actor: ContractActor, deposit_request_txid: Txid) {
        let deposit_txid = actor.deposit_txid;
        self.deposit_request_to_deposit
            .insert(deposit_request_txid, deposit_txid);
        self.actors.insert(deposit_txid, actor);
    }

    /// Removes a [`ContractActor`] by deposit transaction ID.
    pub async fn remove_actor(&mut self, deposit_txid: &Txid) -> Option<ContractActor> {
        if let Some(actor) = self.actors.remove(deposit_txid) {
            // Clean up the deposit_request_txid index.
            // Find and remove the entry that maps to this deposit_txid.
            let deposit_request_txid_to_remove = self.deposit_request_to_deposit.iter().find_map(
                |(deposit_request_txid, mapped_deposit_txid)| {
                    if mapped_deposit_txid == deposit_txid {
                        Some(*deposit_request_txid)
                    } else {
                        None
                    }
                },
            );

            if let Some(deposit_request_txid) = deposit_request_txid_to_remove {
                self.deposit_request_to_deposit
                    .remove(&deposit_request_txid);
            }

            info!(%deposit_txid, "removing contract actor");
            Some(actor)
        } else {
            None
        }
    }

    /// Gets a reference to a [`ContractActor`].
    pub fn get_actor(&self, deposit_txid: &Txid) -> Option<&ContractActor> {
        self.actors.get(deposit_txid)
    }

    /// Gets a reference to a [`ContractActor`] by deposit request transaction ID.
    pub fn get_actor_by_deposit_request_txid(
        &self,
        deposit_request_txid: &Txid,
    ) -> Option<&ContractActor> {
        self.deposit_request_to_deposit
            .get(deposit_request_txid)
            .and_then(|deposit_txid| self.actors.get(deposit_txid))
    }

    /// Gets an [`Iterator`] over all [`ContractActor`]s.
    pub fn actors(&self) -> impl Iterator<Item = (&Txid, &ContractActor)> {
        self.actors.iter()
    }

    /// Gets the number of active [`ContractActor`]s.
    pub fn len(&self) -> usize {
        self.actors.len()
    }

    /// Checks if there are no active [`ContractActor`]s.
    pub fn is_empty(&self) -> bool {
        self.actors.is_empty()
    }

    /// Gracefully shutdowns all [`ContractActor`]s.
    pub async fn shutdown_all(self) {
        info!(num_actors=%self.actors.len(), "shutting down all contract actors");

        let shutdown_futures: Vec<_> = self
            .actors
            .into_iter()
            .map(|(deposit_txid, actor)| async move {
                if let Err(e) = actor.shutdown().await {
                    error!(%deposit_txid, %e, "failed to shutdown contract actor");
                }
            })
            .collect();

        futures::future::join_all(shutdown_futures).await;
        info!("all contract actors shutdown complete");
    }

    /// Removes [`ContractActor`]s for completed contracts (resolved or disproved).
    pub async fn cleanup_completed_contracts(&mut self) {
        let mut to_remove = Vec::new();

        for (deposit_txid, actor) in &self.actors {
            if let Ok(state) = actor.get_state().await {
                if let ContractState::Resolved { .. } = state.state {
                    to_remove.push(*deposit_txid);
                }
            }
        }

        for deposit_txid in to_remove {
            if let Some(actor) = self.remove_actor(&deposit_txid).await {
                info!(%deposit_txid, "cleaning up completed contract");
                if let Err(e) = actor.shutdown().await {
                    error!(%deposit_txid, %e, "failed to shutdown completed contract actor");
                }
            }
        }
    }
}

impl Default for ContractActorManager {
    fn default() -> Self {
        Self::new()
    }
}
