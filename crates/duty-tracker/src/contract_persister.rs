//! This module is responsible for being able to save the contents of the ContractSM to disk.

use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams, StakeChainParams};
use bincode::ErrorKind;
use bitcoin::{Network, Txid};
use sqlx::{
    sqlite::{SqliteQueryResult, SqliteRow},
    Pool, Row, Sqlite,
};
use strata_bridge_tx_graph::transactions::prelude::CovenantTx;
use strata_primitives::params::RollupParams;
use thiserror::Error;

use crate::contract_state_machine::{ContractCfg, ContractSM, MachineState};

/// Error type for the [`ContractPersister`] methods.
#[derive(Debug, Clone, Error)]
pub enum ContractPersistErr {
    /// Unexpected error.
    #[error("Unexpected error: {0}")]
    Unexpected(String),
}

impl From<Box<ErrorKind>> for ContractPersistErr {
    fn from(e: Box<ErrorKind>) -> Self {
        ContractPersistErr::Unexpected(e.to_string())
    }
}

impl From<serde_json::Error> for ContractPersistErr {
    fn from(e: serde_json::Error) -> Self {
        ContractPersistErr::Unexpected(e.to_string())
    }
}

/// System for persisting the relevant data for [`crate::contract_state_machine::ContractSM`]
#[derive(Debug)]
pub struct ContractPersister {
    // TODO(proofofkeags): figure out how to avoid monomorphizing to Sqlite. We'd like the
    // persister to be generalized over SQL implementations.
    pool: Pool<Sqlite>,
}
impl ContractPersister {
    /// Initializes the [`ContractPersister`]
    pub async fn new(pool: Pool<Sqlite>) -> Result<Self, ContractPersistErr> {
        let _: SqliteQueryResult = sqlx::query(
            // TODO(proofofkeags): make state not opaque at the DB level
            r#"
            CREATE TABLE IF NOT EXISTS contracts (
                deposit_txid TEXT PRIMARY KEY,
                deposit_idx INTEGER NOT NULL UNIQUE,
                deposit_tx BLOB NOT NULL,
                operator_table BLOB NOT NULL,
                state BLOB NOT NULL
            )
            "#,
        )
        .execute(&pool)
        .await
        .map_err(|e| ContractPersistErr::Unexpected(e.to_string()))?;
        Ok(ContractPersister { pool })
    }

    /// Initializes a new contract with the given [`ContractCfg`] and [`MachineState`].
    pub async fn init(
        &self,
        cfg: &ContractCfg,
        state: &MachineState,
    ) -> Result<(), ContractPersistErr> {
        let _: SqliteQueryResult = sqlx::query(
            r#"
            INSERT INTO contracts (
                deposit_txid,
                deposit_idx,
                deposit_tx,
                operator_table,
                state
            ) VALUES (?, ?, ?, ?, ?)
            "#,
        )
        .bind(cfg.deposit_tx.compute_txid().to_string())
        .bind(cfg.deposit_idx)
        .bind(bincode::serialize(&cfg.deposit_tx)?)
        .bind(bincode::serialize(&cfg.operator_table)?)
        .bind(bincode::serialize(&state)?)
        .execute(&self.pool)
        .await
        .map_err(|e| ContractPersistErr::Unexpected(e.to_string()))?;
        Ok(())
    }

    /// Updates the [`MachineState`] for a contract.
    pub async fn commit(
        &self,
        deposit_txid: &Txid,
        state: &MachineState,
    ) -> Result<(), ContractPersistErr> {
        let _: SqliteQueryResult = sqlx::query(
            r#"
            UPDATE contracts SET state = ? WHERE deposit_txid = ?
            "#,
        )
        .bind(bincode::serialize(state)?)
        .bind(deposit_txid.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| ContractPersistErr::Unexpected(e.to_string()))?;
        Ok(())
    }

    /// Commits all the machine state in the give contract into the persistence layer.
    pub async fn commit_all(
        &self,
        active_contracts: impl Iterator<Item = (&Txid, &ContractSM)>,
    ) -> Result<(), ContractPersistErr> {
        for (txid, contract_sm) in active_contracts {
            let machine_state = contract_sm.state();
            // FIXME: (@Rajil1213) wrap all commits into a single db transaction.
            self.commit(txid, machine_state).await?;
        }

        Ok(())
    }

    /// Loads both the [`ContractCfg`] and [`MachineState`] from disk for a given [`Txid`].
    pub async fn load(
        &self,
        deposit_txid: Txid,
        network: Network,
        peg_out_graph_params: PegOutGraphParams,
        sidesystem_params: RollupParams,
        connector_params: ConnectorParams,
        stake_chain_params: StakeChainParams,
    ) -> Result<(ContractCfg, MachineState), ContractPersistErr> {
        let row: SqliteRow = sqlx::query(
            r#"
            SELECT
                deposit_idx,
                deposit_tx,
                operator_table,
                state
            FROM contracts WHERE deposit_txid = ?
            "#,
        )
        .bind(deposit_txid.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(|e| ContractPersistErr::Unexpected(e.to_string()))?;
        let deposit_idx = row
            .try_get("deposit_idx")
            .map_err(|e| ContractPersistErr::Unexpected(e.to_string()))?;
        let deposit_tx = bincode::deserialize(
            row.try_get("deposit_tx")
                .map_err(|e| ContractPersistErr::Unexpected(e.to_string()))?,
        )?;
        let operator_table = bincode::deserialize(
            row.try_get("operator_table")
                .map_err(|e| ContractPersistErr::Unexpected(e.to_string()))?,
        )?;
        let state = bincode::deserialize(
            row.try_get("state")
                .map_err(|e| ContractPersistErr::Unexpected(e.to_string()))?,
        )?;

        Ok((
            ContractCfg {
                operator_table,
                deposit_idx,
                deposit_tx,
                network,
                connector_params,
                peg_out_graph_params,
                sidesystem_params,
                stake_chain_params,
            },
            state,
        ))
    }

    /// Loads both the [`ContractCfg`] and [`MachineState`] from disk for all contracts in the
    /// system.
    pub async fn load_all(
        &self,
        network: Network,
        connector_params: ConnectorParams,
        peg_out_graph_params: PegOutGraphParams,
        sidesystem_params: RollupParams,
        stake_chain_params: StakeChainParams,
    ) -> Result<Vec<(ContractCfg, MachineState)>, ContractPersistErr> {
        let rows = sqlx::query(
            r#"
            SELECT
                deposit_idx,
                deposit_tx,
                operator_table,
                state
            FROM contracts
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| ContractPersistErr::Unexpected(e.to_string()))?;
        rows.into_iter()
            .map(|row| {
                let deposit_idx = row
                    .try_get("deposit_idx")
                    .map_err(|e| ContractPersistErr::Unexpected(e.to_string()))?;
                let deposit_tx = bincode::deserialize(
                    row.try_get("deposit_tx")
                        .map_err(|e| ContractPersistErr::Unexpected(e.to_string()))?,
                )?;
                let operator_table = bincode::deserialize(
                    row.try_get("operator_table")
                        .map_err(|e| ContractPersistErr::Unexpected(e.to_string()))?,
                )?;
                let state = bincode::deserialize(
                    row.try_get("state")
                        .map_err(|e| ContractPersistErr::Unexpected(e.to_string()))?,
                )?;
                Ok((
                    ContractCfg {
                        network,
                        operator_table,
                        connector_params,
                        peg_out_graph_params: peg_out_graph_params.clone(),
                        sidesystem_params: sidesystem_params.clone(),
                        stake_chain_params,
                        // later
                        deposit_idx,
                        deposit_tx,
                    },
                    state,
                ))
            })
            .collect::<Result<Vec<_>, _>>()
    }
}
