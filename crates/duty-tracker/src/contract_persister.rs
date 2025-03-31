//! This module is responsible for being able to save the contents of the ContractSM to disk.
use std::fmt::Display;

use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams, StakeChainParams};
use bincode::ErrorKind;
use bitcoin::{Network, Txid};
use sqlx::{
    sqlite::{SqliteQueryResult, SqliteRow},
    Pool, Row, Sqlite,
};
use thiserror::Error;

use crate::contract_state_machine::{ContractCfg, MachineState};

/// Error type for the [`ContractPersister`] methods.
#[derive(Debug, Clone, Error)]
pub struct ContractPersistErr;
impl Display for ContractPersistErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PersistErr")
    }
}
impl From<Box<ErrorKind>> for ContractPersistErr {
    fn from(_: Box<ErrorKind>) -> Self {
        ContractPersistErr
    }
}
impl From<serde_json::Error> for ContractPersistErr {
    fn from(_value: serde_json::Error) -> Self {
        ContractPersistErr
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
                deposit_txid CHAR(64) PRIMARY KEY,
                deposit_idx INTEGER NOT NULL UNIQUE,
                deposit_tx VARBINARY NOT NULL,
                operator_table VARBINARY NOT NULL,
                state VARBINARY NOT NULL,
            );
            "#,
        )
        .execute(&pool)
        .await
        .map_err(|_| ContractPersistErr)?;
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
        .map_err(|_| ContractPersistErr)?;
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
            UPDATE contracts SET state = ? WHERE deposit_txid = ?;
            "#,
        )
        .bind(bincode::serialize(state)?)
        .bind(deposit_txid.to_string())
        .execute(&self.pool)
        .await
        .map_err(|_| ContractPersistErr)?;
        Ok(())
    }

    /// Loads both the [`ContractCfg`] and [`MachineState`] from disk for a given [`Txid`].
    pub async fn load(
        &self,
        deposit_txid: Txid,
        network: Network,
        peg_out_graph_params: PegOutGraphParams,
        connector_params: ConnectorParams,
        stake_chain_params: StakeChainParams,
    ) -> Result<(ContractCfg, MachineState), ContractPersistErr> {
        let row: SqliteRow = sqlx::query(
            r#"
            SELECT (
                deposit_idx,
                deposit_tx,
                operator_table,
                state
            ) FROM contracts WHERE deposit_txid = ?
            "#,
        )
        .bind(deposit_txid.to_string())
        .fetch_one(&self.pool)
        .await
        .map_err(|_| ContractPersistErr)?;
        let deposit_idx = row.try_get("deposit_idx").map_err(|_| ContractPersistErr)?;
        let deposit_tx =
            bincode::deserialize(row.try_get("deposit_tx").map_err(|_| ContractPersistErr)?)?;
        let operator_table = bincode::deserialize(
            row.try_get("operator_table")
                .map_err(|_| ContractPersistErr)?,
        )?;
        let state = bincode::deserialize(row.try_get("state").map_err(|_| ContractPersistErr)?)?;

        Ok((
            ContractCfg {
                operator_table,
                deposit_idx,
                deposit_tx,
                network,
                connector_params,
                peg_out_graph_params,
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
        stake_chain_params: StakeChainParams,
    ) -> Result<Vec<(ContractCfg, MachineState)>, ContractPersistErr> {
        let rows = sqlx::query(
            r#"
            SELECT (
                deposit_idx,
                deposit_tx,
                operator_table,
                state
            ) FROM contracts
            "#,
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| ContractPersistErr)?;
        rows.into_iter()
            .map(|row| {
                let deposit_idx = row.try_get("deposit_idx").map_err(|_| ContractPersistErr)?;
                let deposit_tx = bincode::deserialize(
                    row.try_get("deposit_tx").map_err(|_| ContractPersistErr)?,
                )?;
                let operator_table = bincode::deserialize(
                    row.try_get("operator_table")
                        .map_err(|_| ContractPersistErr)?,
                )?;
                let state =
                    bincode::deserialize(row.try_get("state").map_err(|_| ContractPersistErr)?)?;
                Ok((
                    ContractCfg {
                        network,
                        operator_table,
                        connector_params,
                        peg_out_graph_params: peg_out_graph_params.clone(),
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
