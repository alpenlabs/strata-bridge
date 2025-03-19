//! This module is responsible for being able to save the contents of the ContractSM to disk.
use std::fmt::Display;

use alpen_bridge_params::prelude::ConnectorParams;
use bincode::ErrorKind;
use bitcoin::Txid;
use sqlx::{
    sqlite::{SqliteQueryResult, SqliteRow},
    Pool, Row, Sqlite,
};
use strata_bridge_tx_graph::transactions::payout_optimistic;
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
                payout_optimistic_timelock INTEGER NOT NULL,
                pre_assert_timelock INTEGER NOT NULL,
                payout_timelock INTEGER NOT NULL,
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
                network,
                operator_table,
                payout_optimistic_timelock,
                pre_assert_timelock,
                payout_timelock,
                state
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(cfg.deposit_tx.compute_txid().to_string())
        .bind(cfg.deposit_idx)
        .bind(bincode::serialize(&cfg.deposit_tx)?)
        .bind(serde_json::to_string(&cfg.network)?)
        .bind(bincode::serialize(&cfg.operator_table)?)
        .bind(cfg.connector_params.payout_optimistic_timelock)
        .bind(cfg.connector_params.pre_assert_timelock)
        .bind(cfg.connector_params.payout_timelock)
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
    ) -> Result<(ContractCfg, MachineState), ContractPersistErr> {
        let row: SqliteRow = sqlx::query(
            r#"
            SELECT (
                deposit_idx,
                deposit_tx,
                network,
                operator_table,
                payout_optimistic_timelock,
                pre_assert_timelock,
                payout_timelock,
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
        let network =
            serde_json::from_str(row.try_get("network").map_err(|_| ContractPersistErr)?)?;
        let operator_table = bincode::deserialize(
            row.try_get("operator_table")
                .map_err(|_| ContractPersistErr)?,
        )?;
        let payout_optimistic_timelock = row
            .try_get("payout_optimistic_timelock")
            .map_err(|_| ContractPersistErr)?;
        let pre_assert_timelock = row
            .try_get("pre_assert_timelock")
            .map_err(|_| ContractPersistErr)?;
        let payout_timelock = row
            .try_get("payout_timelock")
            .map_err(|_| ContractPersistErr)?;
        let state = bincode::deserialize(row.try_get("state").map_err(|_| ContractPersistErr)?)?;
        Ok((
            ContractCfg {
                network,
                operator_table,
                connector_params: ConnectorParams {
                    payout_optimistic_timelock,
                    pre_assert_timelock,
                    payout_timelock,
                },
                deposit_idx,
                deposit_tx,
            },
            state,
        ))
    }

    /// Loads both the [`ContractCfg`] and [`MachineState`] from disk for all contracts in the
    /// system.
    pub async fn load_all(&self) -> Result<Vec<(ContractCfg, MachineState)>, ContractPersistErr> {
        let rows = sqlx::query(
            r#"
            SELECT (
                deposit_idx,
                deposit_tx,
                network,
                operator_table,
                payout_optimistic_timelock,
                pre_assert_timelock,
                payout_timelock,
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
                let network =
                    serde_json::from_str(row.try_get("network").map_err(|_| ContractPersistErr)?)?;
                let operator_table = bincode::deserialize(
                    row.try_get("operator_table")
                        .map_err(|_| ContractPersistErr)?,
                )?;
                let payout_optimistic_timelock = row
                    .try_get("payout_optimistic_timelock")
                    .map_err(|_| ContractPersistErr)?;
                let pre_assert_timelock = row
                    .try_get("pre_assert_timelock")
                    .map_err(|_| ContractPersistErr)?;
                let payout_timelock = row
                    .try_get("payout_timelock")
                    .map_err(|_| ContractPersistErr)?;
                let state =
                    bincode::deserialize(row.try_get("state").map_err(|_| ContractPersistErr)?)?;
                Ok((
                    ContractCfg {
                        network,
                        operator_table,
                        connector_params: ConnectorParams {
                            payout_optimistic_timelock,
                            pre_assert_timelock,
                            payout_timelock,
                        },
                        deposit_idx,
                        deposit_tx,
                    },
                    state,
                ))
            })
            .collect::<Result<Vec<_>, _>>()
    }
}
