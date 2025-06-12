//! Actor-based wrapper around [`ContractSM`] that allows each contract to run in its own task,
//! enabling parallel processing of independent contracts.

use std::{collections::BTreeMap, sync::Arc};

use bitcoin::{Transaction, Txid};
use strata_bridge_tx_graph::transactions::covenant_tx::CovenantTx;
use tokio::{
    sync::{mpsc, oneshot},
    task::JoinHandle,
};
use tracing::{debug, error, info, warn};

use crate::{
    contract_persister::{ContractPersistErr, ContractPersister},
    contract_state_machine::{
        ContractCfg, ContractEvent, ContractSM, MachineState, OperatorDuty, TransitionErr,
    },
    stake_chain_persister::StakeChainPersister,
};

/// Message types that can be sent to a [`ContractActor`].
#[expect(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum ContractActorMessage {
    /// Process a [`ContractEvent`] and return resulting [`OperatorDuty`]s.
    ProcessEvent {
        /// The [`ContractEvent`] to process.
        event: ContractEvent,

        /// Channel to send the response back.
        respond_to: oneshot::Sender<Result<Vec<OperatorDuty>, TransitionErr>>,
    },

    /// Gets the current [`MachineState`] of the contract.
    GetState {
        /// Channel to send the response back
        respond_to: oneshot::Sender<MachineState>,
    },

    /// Gets the [`ContractCfg`] of the contract.
    GetConfig {
        /// Channel to send the response back
        respond_to: oneshot::Sender<ContractCfg>,
    },

    /// Checks if the contract handles a specific bitcoin [`Transaction`].
    TransactionFilter {
        /// The bitcoin [`Transaction`] to check.
        tx: Transaction,

        /// Channel to send the response back.
        respond_to: oneshot::Sender<bool>,
    },

    /// Gets claim transaction IDs for this contract.
    GetClaimTxids {
        /// Channel to send the response back.
        respond_to: oneshot::Sender<Vec<Txid>>,
    },

    /// Gets the deposit transaction ID.
    GetDepositTxid {
        /// Channel to send the response back.
        respond_to: oneshot::Sender<Txid>,
    },

    /// Gets the deposit request transaction ID.
    GetDepositRequestTxid {
        /// Channel to send the response back.
        respond_to: oneshot::Sender<Txid>,
    },

    /// Gets the withdrawal request transaction ID (if any).
    GetWithdrawalRequestTxid {
        /// Channel to send the response back.
        respond_to: oneshot::Sender<Option<Txid>>,
    },

    /// Gets the withdrawal fulfillment transaction ID (if any).
    GetWithdrawalFulfillmentTxid {
        /// Channel to send the response back.
        respond_to: oneshot::Sender<Option<Txid>>,
    },

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
                    ContractActorMessage::ProcessEvent { event, respond_to } => {
                        debug!(%deposit_txid, ?event, "processing contract event");

                        let result = csm.process_contract_event(event);

                        // Persist state after successful processing
                        if result.is_ok() {
                            if let Err(e) =
                                Self::persist_state(&csm, &state_handles.contract_persister).await
                            {
                                error!(%deposit_txid, %e, "failed to persist CSM state after event processing");
                                // Don't fail the event processing due to persistence errors
                                // The state is still updated in memory
                                warn!(%deposit_txid, "continuing with in-memory state despite persistence failure");
                            }
                        }

                        let _ = respond_to.send(result);
                    }
                    ContractActorMessage::GetState { respond_to } => {
                        let _ = respond_to.send(csm.state().clone());
                    }
                    ContractActorMessage::GetConfig { respond_to } => {
                        let _ = respond_to.send(csm.cfg().clone());
                    }
                    ContractActorMessage::TransactionFilter { tx, respond_to } => {
                        let result = csm.transaction_filter(&tx);
                        let _ = respond_to.send(result);
                    }
                    ContractActorMessage::GetClaimTxids { respond_to } => {
                        let claim_txids = csm.claim_txids();
                        let _ = respond_to.send(claim_txids);
                    }
                    ContractActorMessage::GetDepositTxid { respond_to } => {
                        let _ = respond_to.send(csm.deposit_txid());
                    }
                    ContractActorMessage::GetDepositRequestTxid { respond_to } => {
                        let _ = respond_to.send(csm.deposit_request_txid());
                    }
                    ContractActorMessage::GetWithdrawalRequestTxid { respond_to } => {
                        let _ = respond_to.send(csm.withdrawal_request_txid());
                    }
                    ContractActorMessage::GetWithdrawalFulfillmentTxid { respond_to } => {
                        let _ = respond_to.send(csm.withdrawal_fulfillment_txid());
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
        let (sender, receiver) = oneshot::channel();
        self.event_sender
            .send(ContractActorMessage::ProcessEvent {
                event,
                respond_to: sender,
            })
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver
            .await
            .map_err(|_| TransitionErr("Failed to receive response from CSM actor".to_string()))?
    }

    /// Gets the current [`MachineState`] of the contract.
    pub async fn get_state(&self) -> Result<MachineState, TransitionErr> {
        let (sender, receiver) = oneshot::channel();
        self.event_sender
            .send(ContractActorMessage::GetState { respond_to: sender })
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver
            .await
            .map_err(|_| TransitionErr("Failed to receive state from CSM actor".to_string()))
    }

    /// Gets the contract [`ContractCfg`].
    pub async fn get_config(&self) -> Result<ContractCfg, TransitionErr> {
        let (sender, receiver) = oneshot::channel();
        self.event_sender
            .send(ContractActorMessage::GetConfig { respond_to: sender })
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver
            .await
            .map_err(|_| TransitionErr("Failed to receive config from CSM actor".to_string()))
    }

    /// Checks if the contract handles a specific transaction.
    pub async fn transaction_filter(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Result<bool, TransitionErr> {
        let (sender, receiver) = oneshot::channel();
        self.event_sender
            .send(ContractActorMessage::TransactionFilter {
                tx: tx.clone(),
                respond_to: sender,
            })
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver.await.map_err(|_| {
            TransitionErr("Failed to receive filter result from CSM actor".to_string())
        })
    }

    /// Gets claim transaction IDs for this contract.
    pub async fn claim_txids(&self) -> Result<Vec<Txid>, TransitionErr> {
        let (sender, receiver) = oneshot::channel();
        self.event_sender
            .send(ContractActorMessage::GetClaimTxids { respond_to: sender })
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver
            .await
            .map_err(|_| TransitionErr("Failed to receive claim txids from CSM actor".to_string()))
    }

    /// Gets the deposit request transaction ID.
    pub async fn deposit_request_txid(&self) -> Result<Txid, TransitionErr> {
        let (sender, receiver) = oneshot::channel();
        self.event_sender
            .send(ContractActorMessage::GetDepositRequestTxid { respond_to: sender })
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver.await.map_err(|_| {
            TransitionErr("Failed to receive deposit request txid from CSM actor".to_string())
        })
    }

    /// Gets the withdrawal request transaction ID (if any).
    pub async fn withdrawal_request_txid(&self) -> Result<Option<Txid>, TransitionErr> {
        let (sender, receiver) = oneshot::channel();
        self.event_sender
            .send(ContractActorMessage::GetWithdrawalRequestTxid { respond_to: sender })
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver.await.map_err(|_| {
            TransitionErr("Failed to receive withdrawal request txid from CSM actor".to_string())
        })
    }

    /// Get the withdrawal fulfillment transaction ID (if any).
    pub async fn withdrawal_fulfillment_txid(&self) -> Result<Option<Txid>, TransitionErr> {
        let (sender, receiver) = oneshot::channel();
        self.event_sender
            .send(ContractActorMessage::GetWithdrawalFulfillmentTxid { respond_to: sender })
            .map_err(|_| TransitionErr("CSM actor has shut down".to_string()))?;

        receiver.await.map_err(|_| {
            TransitionErr(
                "Failed to receive withdrawal fulfillment txid from CSM actor".to_string(),
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
                result.map_err(|e| TransitionErr(format!("Actor task panicked: {}", e)))?;
                Ok(())
            }
            Err(_) => {
                warn!(deposit_txid=%self.deposit_txid, "Actor shutdown timed out, aborting");
                // Handle was moved into timeout, so we need to create a new abort mechanism
                // In this case, the timeout already happened, so the task should be dropped
                Err(TransitionErr("Actor shutdown timed out".to_string()))
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
}

impl ContractActorManager {
    /// Creates a new empty [`ContractActorManager`].
    pub const fn new() -> Self {
        Self {
            actors: BTreeMap::new(),
        }
    }

    /// Adds a new [`ContractActor`].
    pub fn add_actor(&mut self, actor: ContractActor) {
        self.actors.insert(actor.deposit_txid, actor);
    }

    /// Removes a [`ContractActor`] by deposit transaction ID.
    pub async fn remove_actor(&mut self, deposit_txid: &Txid) -> Option<ContractActor> {
        if let Some(actor) = self.actors.remove(deposit_txid) {
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
                use crate::contract_state_machine::ContractState;
                match state.state {
                    ContractState::Resolved { .. } | ContractState::Disproved { .. } => {
                        to_remove.push(*deposit_txid);
                    }
                    _ => {}
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
