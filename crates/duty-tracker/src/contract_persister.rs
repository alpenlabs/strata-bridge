//! TODO(proofofkeags): module docs
use std::fmt::Display;

use bincode::ErrorKind;
use bitcoin::Txid;
use sqlx::{
    sqlite::{SqliteQueryResult, SqliteRow},
    Pool, Row, Sqlite,
};
use thiserror::Error;

use crate::contract_state_machine::{ContractCfg, MachineState};

/// Error type for the [`ContractPersister`] methods.
#[derive(Debug, Clone, Error)]
pub struct PersistErr;
impl Display for PersistErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PersistErr")
    }
}
impl From<Box<ErrorKind>> for PersistErr {
    fn from(_: Box<ErrorKind>) -> Self {
        PersistErr
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
    pub async fn new(pool: Pool<Sqlite>) -> Result<Self, PersistErr> {
        let _: SqliteQueryResult = sqlx::query(
            // TODO(proofofkeags): make state not opaque at the DB level
            r#"
            CREATE TABLE IF NOT EXISTS contracts (
                deposit_txid CHAR(64) NOT NULL UNIQUE,
                deposit_tx VARBINARY NOT NULL,
                operator_set VARBINARY NOT NULL,
                perspective SMALLINT NOT NULL,
                peg_out_graphs VARBINARY NOT NULL,
                state VARBINARY NOT NULL,
            );
            "#,
        )
        .execute(&pool)
        .await
        .map_err(|_| PersistErr)?;
        Ok(ContractPersister { pool })
    }

    /// Initializes a new contract with the given [`ContractCfg`] and [`MachineState`].
    pub async fn init(&self, cfg: &ContractCfg, state: &MachineState) -> Result<(), PersistErr> {
        let _: SqliteQueryResult = sqlx::query(
            r#"
            INSERT INTO contracts (deposit_txid, deposit_tx, operator_set, perspective, state) VALUES (?, ?, ?, ?, ?)
            "#
        )
        .bind(cfg.deposit_tx.compute_txid().to_string())
        .bind(bincode::serialize(&cfg.deposit_tx)?)
        .bind(bincode::serialize(&cfg.operator_set)?)
        .bind(cfg.perspective)
        .bind(bincode::serialize(&cfg.peg_out_graphs)?)
        .bind(bincode::serialize(&state)?)
        .execute(&self.pool)
        .await
        .map_err(|_|PersistErr)?;
        Ok(())
    }

    /// Updates the [`MachineState`] for a contract.
    pub async fn commit(
        &self,
        deposit_txid: &Txid,
        state: &MachineState,
    ) -> Result<(), PersistErr> {
        let _: SqliteQueryResult = sqlx::query(
            r#"
            UPDATE contracts SET state = ? WHERE deposit_txid = ?;
            "#,
        )
        .bind(bincode::serialize(state)?)
        .bind(deposit_txid.to_string())
        .execute(&self.pool)
        .await
        .map_err(|_| PersistErr)?;
        Ok(())
    }

    /// Loads both the [`ContractCfg`] and [`MachineState`] from disk for a given [`Txid`].
    pub async fn load(
        &self,
        deposit_txid: Txid,
    ) -> Result<(ContractCfg, MachineState), PersistErr> {
        let row: SqliteRow = sqlx::query(
            r#"
            SELECT (deposit_idx, deposit_tx, operator_set, perspective, peg_out_graphs, state) FROM contracts WHERE deposit_txid = ?
            "#
        ).bind(deposit_txid.to_string()).fetch_one(&self.pool).await.map_err(|_|PersistErr)?;
        let deposit_tx = bincode::deserialize(row.try_get("deposit_tx").map_err(|_| PersistErr)?)?;
        let perspective = row.try_get("perspective").map_err(|_| PersistErr)?;
        let operator_set =
            bincode::deserialize(row.try_get("operator_set").map_err(|_| PersistErr)?)?;
        let peg_out_graphs =
            bincode::deserialize(row.try_get("peg_out_graphs").map_err(|_| PersistErr)?)?;
        let state = bincode::deserialize(row.try_get("state").map_err(|_| PersistErr)?)?;
        Ok((
            ContractCfg {
                perspective,
                operator_set,
                deposit_tx,
                peg_out_graphs,
            },
            state,
        ))
    }

    /// Loads both the [`ContractCfg`] and [`MachineState`] from disk for all contracts in the
    /// system.
    pub async fn load_all(&self) -> Result<Vec<(ContractCfg, MachineState)>, PersistErr> {
        let rows = sqlx::query(
            r#"
            SELECT (deposit_idx, deposit_tx, operator_set, perspective, peg_out_graphs, state) FROM contracts
            "#
        ).fetch_all(&self.pool).await.map_err(|_|PersistErr)?;
        rows.into_iter()
            .map(|row| {
                let deposit_tx =
                    bincode::deserialize(row.try_get("deposit_tx").map_err(|_| PersistErr)?)?;
                let perspective = row.try_get("perspective").map_err(|_| PersistErr)?;
                let operator_set =
                    bincode::deserialize(row.try_get("operator_set").map_err(|_| PersistErr)?)?;
                let peg_out_graphs =
                    bincode::deserialize(row.try_get("peg_out_graphs").map_err(|_| PersistErr)?)?;
                let state = bincode::deserialize(row.try_get("state").map_err(|_| PersistErr)?)?;
                Ok((
                    ContractCfg {
                        perspective,
                        operator_set,
                        deposit_tx,
                        peg_out_graphs,
                    },
                    state,
                ))
            })
            .collect::<Result<Vec<_>, _>>()
    }
}
