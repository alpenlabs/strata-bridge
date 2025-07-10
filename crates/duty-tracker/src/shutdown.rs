//! Shutdown handler for the duty tracker.
//!
//! This module implements persistence of critical in-memory state before shutdown.

use std::{collections::BTreeMap, time::Duration};

use bitcoin::Txid;
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_tasks::ShutdownGuard;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use crate::{
    contract_persister::ContractPersister, contract_state_machine::ContractSM, errors::ShutdownErr,
    stake_chain_persister::StakeChainPersister, stake_chain_state_machine::StakeChainSM,
};

/// Execution state that needs to be persisted before shutdown.
#[derive(Debug)]
pub struct ExecutionState {
    /// Active contracts state.
    pub active_contracts: BTreeMap<Txid, ContractSM>,

    /// Claim transaction IDs state map.
    pub claim_txids: BTreeMap<Txid, Txid>,

    /// Stake chain state.
    pub stake_chains: StakeChainSM,

    /// Operator table for stake chain persistence.
    pub operator_table: OperatorTable,
}

/// Shutdown handler for the duty tracker.
#[derive(Debug)]
pub struct ShutdownHandler {
    /// [`ContractPersister`] handle for persisting contract state.
    contract_persister: ContractPersister,

    /// [`StakeChainPersister`] handle for persisting stake chain state.
    stake_chain_persister: StakeChainPersister,
}

impl ShutdownHandler {
    /// Creates a new [`ShutdownHandler`] with the given persisters.
    pub const fn new(
        contract_persister: ContractPersister,
        stake_chain_persister: StakeChainPersister,
    ) -> Self {
        Self {
            contract_persister,
            stake_chain_persister,
        }
    }

    /// Persists all critical state before shutdown.
    pub async fn persist_state_before_shutdown(
        &self,
        execution_state: &ExecutionState,
        shutdown_guard: &ShutdownGuard,
        shutdown_timeout: Duration,
    ) -> Result<(), ShutdownErr> {
        info!("initiating shutdown - persisting critical state");

        // Check if we should shutdown before starting.
        if shutdown_guard.should_shutdown() {
            warn!("shutdown requested before state persistence started");
            return Ok(());
        }

        // Persist contract state with timeout.
        let contract_result = timeout(
            shutdown_timeout,
            self.persist_contract_state(execution_state, shutdown_guard),
        )
        .await;

        match contract_result {
            Ok(Ok(())) => {
                info!("contract state persisted successfully");
            }
            Ok(Err(e)) => {
                error!("failed to persist contract state: {e:?}");
                return Err(e);
            }
            Err(_) => {
                error!("timeout persisting contract state");
                return Err(ShutdownErr::ShutdownTimeout(
                    "timeout persisting contract state".to_string(),
                ));
            }
        }

        // Check shutdown again.
        if shutdown_guard.should_shutdown() {
            warn!("shutdown requested during state persistence");
            return Ok(());
        }

        // Persist stake chain state with timeout.
        let stake_result = timeout(
            shutdown_timeout,
            self.persist_stake_chain_state(execution_state, shutdown_guard),
        )
        .await;

        match stake_result {
            Ok(Ok(())) => {
                info!("stake chain state persisted successfully");
            }
            Ok(Err(e)) => {
                error!("failed to persist stake chain state: {e:?}");
                return Err(e);
            }
            Err(_) => {
                error!("timeout persisting stake chain state");
                return Err(ShutdownErr::ShutdownTimeout(
                    "timeout persisting stake chain state".to_string(),
                ));
            }
        }

        info!("shutdown - all critical state persisted successfully");
        Ok(())
    }

    /// Persists contract state.
    async fn persist_contract_state(
        &self,
        execution_state: &ExecutionState,
        shutdown_guard: &ShutdownGuard,
    ) -> Result<(), ShutdownErr> {
        debug!("persisting contract state");

        if shutdown_guard.should_shutdown() {
            warn!("shutdown requested before contract persistence");
            return Ok(());
        }

        self.contract_persister
            .commit_all(execution_state.active_contracts.iter())
            .await?;

        debug!("contract state persistence completed");
        Ok(())
    }

    /// Persists stake chain state.
    async fn persist_stake_chain_state(
        &self,
        execution_state: &ExecutionState,
        shutdown_guard: &ShutdownGuard,
    ) -> Result<(), ShutdownErr> {
        debug!("persisting stake chain state");

        if shutdown_guard.should_shutdown() {
            warn!("shutdown requested before stake chain persistence");
            return Ok(());
        }

        let stake_chain_state = execution_state.stake_chains.state().clone();

        self.stake_chain_persister
            .commit_stake_data(&execution_state.operator_table, stake_chain_state)
            .await?;

        debug!("stake chain state persistence completed");
        Ok(())
    }
}
