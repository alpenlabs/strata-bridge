//! This module is responsible for being able to save the contents of the ContractSM to disk.

use alpen_bridge_params::prelude::{ConnectorParams, PegOutGraphParams, StakeChainParams};
use bincode::ErrorKind;
use bitcoin::{Network, Txid};
use sqlx::{
    sqlite::{SqliteQueryResult, SqliteRow},
    Pool, Row, Sqlite,
};
use strata_bridge_db::{
    errors::DbError,
    persistent::{config::DbConfig, errors::StorageError, sqlite::execute_with_retries},
};
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_tx_graph::transactions::{deposit::DepositTx, prelude::CovenantTx};
use strata_primitives::params::RollupParams;
use thiserror::Error;
use tracing::{debug, error};

use crate::contract_state_machine::{ContractCfg, ContractSM, MachineState};

/// Error type for the [`ContractPersister`] methods.
#[derive(Debug, Clone, Error)]
pub enum ContractPersistErr {
    /// Unexpected error.
    #[error("unexpected error: {0}")]
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

impl From<DbError> for ContractPersistErr {
    fn from(e: DbError) -> Self {
        ContractPersistErr::Unexpected(e.to_string())
    }
}

impl From<ContractPersistErr> for DbError {
    fn from(e: ContractPersistErr) -> Self {
        DbError::Unexpected(e.to_string())
    }
}

impl From<StorageError> for ContractPersistErr {
    fn from(e: StorageError) -> Self {
        ContractPersistErr::Unexpected(e.to_string())
    }
}

impl From<ContractPersistErr> for StorageError {
    fn from(e: ContractPersistErr) -> Self {
        StorageError::InvalidData(e.to_string())
    }
}

/// System for persisting the relevant data for [`crate::contract_state_machine::ContractSM`].
#[derive(Debug)]
pub struct ContractPersister {
    /// Database SQLite Pool.
    // TODO(proofofkeags): figure out how to avoid monomorphizing to Sqlite. We'd like the
    // persister to be generalized over SQL implementations.
    pool: Pool<Sqlite>,

    /// Database configuration.
    config: DbConfig,
}
impl ContractPersister {
    /// Initializes the [`ContractPersister`].
    pub async fn new(pool: Pool<Sqlite>, config: DbConfig) -> Result<Self, ContractPersistErr> {
        execute_with_retries(&config, || async {
            let _: SqliteQueryResult = sqlx::query(
                // TODO(proofofkeags): make state not opaque at the DB level
                r#"
            CREATE TABLE IF NOT EXISTS contracts (
                deposit_txid TEXT PRIMARY KEY,
                deposit_idx INTEGER NOT NULL UNIQUE,
                deposit_tx BLOB NOT NULL,
                operator_table BLOB NOT NULL,
                state TEXT NOT NULL
            )
            "#,
            )
            .execute(&pool)
            .await
            .map_err(|e| {
                error!(?e, "failed to create contracts table");
                StorageError::from(e)
            })?;
            Ok(())
        })
        .await
        .map_err(ContractPersistErr::from)?;

        Ok(ContractPersister { pool, config })
    }

    /// Initializes a new contract with the given [`ContractCfg`] and [`MachineState`].
    pub async fn init(
        &self,
        cfg: &ContractCfg,
        state: &MachineState,
    ) -> Result<(), ContractPersistErr> {
        let deposit_tx_bytes = bincode::serialize(&cfg.deposit_tx)?;
        let operator_table_bytes = bincode::serialize(&cfg.operator_table)?;
        let state_json = serde_json::to_string(&state)?;

        execute_with_retries(&self.config, || async {
            // Begin transaction
            let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

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
            .bind(&deposit_tx_bytes)
            .bind(&operator_table_bytes)
            .bind(&state_json)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!(?e, "failed to insert contract into database");
                StorageError::from(e)
            })?;

            // Commit the transaction
            tx.commit().await.map_err(|e| {
                error!(
                    ?e,
                    "failed to commit transaction for contract initialization"
                );
                StorageError::from(e)
            })?;

            Ok(())
        })
        .await
        .map_err(ContractPersistErr::from)?;

        Ok(())
    }

    /// Updates the [`MachineState`] for a contract.
    pub async fn commit(
        &self,
        deposit_txid: &Txid,
        deposit_idx: u32,
        deposit_tx: &DepositTx,
        operator_table: &OperatorTable,
        state: &MachineState,
    ) -> Result<(), ContractPersistErr> {
        let deposit_tx_bytes = bincode::serialize(&deposit_tx)?;
        let operator_table_bytes = bincode::serialize(&operator_table)?;
        let state_json = serde_json::to_string(&state)?;

        execute_with_retries(&self.config, || async {
            // Begin transaction
            let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

            let _: SqliteQueryResult = sqlx::query(
                r#"
                INSERT OR REPLACE INTO contracts (deposit_txid, deposit_idx, deposit_tx, operator_table, state)
                VALUES (?, ?, ?, ?, ?)
                "#,
            )
            .bind(deposit_txid.to_string())
            .bind(deposit_idx)
            .bind(&deposit_tx_bytes)
            .bind(&operator_table_bytes)
            .bind(&state_json)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!(?e, %deposit_txid, "failed to commit machine state to disk");
                StorageError::from(e)
            })?;

            // Commit the transaction
            tx.commit().await.map_err(|e| {
                error!(?e, %deposit_txid, "failed to commit transaction for machine state");
                StorageError::from(e)
            })?;

            Ok(())
        })
        .await
        .map_err(|e| {
            error!(?e, %deposit_txid, "failed to commit machine state to disk");
            ContractPersistErr::from(e)
        })?;

        Ok(())
    }

    /// Commits all the machine state in the give contract into the persistence layer.
    pub async fn commit_all(
        &self,
        active_contracts: impl Iterator<Item = (&Txid, &ContractSM)>,
    ) -> Result<(), ContractPersistErr> {
        // Collect all contract data first
        let contracts_data: Vec<_> = active_contracts
            .map(|(txid, contract_sm)| {
                let deposit_idx = contract_sm.cfg().deposit_idx;
                let deposit_tx = &contract_sm.cfg().deposit_tx;
                let operator_table = &contract_sm.cfg().operator_table;
                let machine_state = contract_sm.state();

                let deposit_tx_bytes = bincode::serialize(&deposit_tx)?;
                let operator_table_bytes = bincode::serialize(&operator_table)?;
                let state_json = serde_json::to_string(&machine_state)?;

                Ok((
                    txid.to_string(),
                    deposit_idx,
                    deposit_tx_bytes,
                    operator_table_bytes,
                    state_json,
                ))
            })
            .collect::<Result<Vec<_>, ContractPersistErr>>()?;

        if contracts_data.is_empty() {
            return Ok(());
        }

        let num_contracts = contracts_data.len();
        debug!(%num_contracts, "committing all active contracts");

        execute_with_retries(&self.config, || async {
            // Begin transaction
            let mut tx = self.pool.begin().await.map_err(StorageError::from)?;

            // Insert each contract within the transaction
            for (deposit_txid, deposit_idx, deposit_tx_bytes, operator_table_bytes, state_json) in &contracts_data {
                let _: SqliteQueryResult = sqlx::query(
                    r#"
                    INSERT OR REPLACE INTO contracts (deposit_txid, deposit_idx, deposit_tx, operator_table, state)
                    VALUES (?, ?, ?, ?, ?)
                    "#,
                )
                .bind(deposit_txid)
                .bind(deposit_idx)
                .bind(deposit_tx_bytes)
                .bind(operator_table_bytes)
                .bind(state_json)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    error!(?e, %deposit_txid, "failed to insert contract into transaction");
                    StorageError::from(e)
                })?;
            }

            // Commit the transaction
            tx.commit().await.map_err(|e| {
                error!(?e, "failed to commit transaction for all contracts");
                StorageError::from(e)
            })?;

            Ok(())
        })
        .await
        .map_err(ContractPersistErr::from)?;

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
        let result = execute_with_retries(&self.config, || async {
                let sidesystem_params = sidesystem_params.clone();
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
                .map_err(|e| {
                    error!(?e, %deposit_txid, "could not load contract from disk");
                    StorageError::from(e)
                })?;

                let deposit_idx = row.try_get("deposit_idx").map_err(|e| {
                    error!(?e, %deposit_txid, "could not parse deposit_idx from contract entry in disk");
                    StorageError::from(e)
                })?;

                let deposit_tx_bytes = row.try_get::<Vec<u8>, _>("deposit_tx").map_err(|e| {
                    error!(?e, %deposit_txid, "could not parse deposit_tx from contract entry in disk");
                    StorageError::from(e)
                })?;

                let deposit_tx = bincode::deserialize(&deposit_tx_bytes).map_err(|e| {
                    error!(?e, %deposit_txid, "could not deserialize deposit_tx from contract entry in disk");
                    ContractPersistErr::from(e)
                })?;

                let operator_table_bytes = row.try_get::<Vec<u8>, _>("operator_table").map_err(|e| {
                    error!(?e, %deposit_txid, "could not parse operator_table from contract entry in disk");
                    StorageError::from(e)
                })?;

                let operator_table = bincode::deserialize(&operator_table_bytes).map_err(|e| {
                    error!(?e, %deposit_txid, "could not deserialize operator_table from contract entry in disk");
                    ContractPersistErr::from(e)
                })?;

                let state_json = row.try_get::<String, _>("state").map_err(|e| {
                    error!(?e, %deposit_txid, "could not parse state from contract entry in disk");
                    StorageError::from(e)
                })?;

                let state: MachineState = serde_json::from_str(&state_json).map_err(|e| {
                    error!(?e, %deposit_txid, "could not deserialize state from contract entry in disk");
                    ContractPersistErr::from(e)
                })?;

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
            })
            .await
            .map_err(ContractPersistErr::from)?;

        Ok(result)
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
        let result = execute_with_retries(&self.config, || async {
            let sidesystem_params = sidesystem_params.clone();
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
            .map_err(|e| {
                error!(?e, "could not load all contracts from disk");
                ContractPersistErr::Unexpected(e.to_string())
            })?;

            rows.into_iter()
                .map(|row| {
                    let deposit_idx = row.try_get("deposit_idx").map_err(|e| {
                        error!(
                            ?e,
                            "could not parse deposit_idx from contract entry in disk"
                        );
                        ContractPersistErr::Unexpected(e.to_string())
                    })?;

                    let deposit_tx =
                        bincode::deserialize(row.try_get("deposit_tx").map_err(|e| {
                            error!(?e, "could not parse deposit_tx from contract entry in disk");
                            ContractPersistErr::Unexpected(e.to_string())
                        })?)
                        .map_err(|e| {
                            error!(
                                ?e,
                                "could not deserialize deposit_tx from contract entry in disk"
                            );
                            ContractPersistErr::Unexpected(e.to_string())
                        })?;

                    let operator_table =
                        bincode::deserialize(row.try_get("operator_table").map_err(|e| {
                            error!(
                                ?e,
                                "could not parse operator_table from contract entry in disk"
                            );
                            ContractPersistErr::Unexpected(e.to_string())
                        })?)
                        .map_err(|e| {
                            error!(
                                ?e,
                                "could not deserialize operator_table from contract entry in disk"
                            );
                            ContractPersistErr::Unexpected(e.to_string())
                        })?;

                    let state = serde_json::from_str(row.try_get("state").map_err(|e| {
                        error!(?e, "could not parse state from contract entry in disk");
                        ContractPersistErr::Unexpected(e.to_string())
                    })?)
                    .map_err(|e| {
                        error!(
                            ?e,
                            "could not deserialize state from contract entry in disk"
                        );
                        ContractPersistErr::Unexpected(e.to_string())
                    })?;

                    Ok((
                        ContractCfg {
                            network,
                            operator_table,
                            connector_params,
                            peg_out_graph_params,
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
        })
        .await
        .map_err(ContractPersistErr::from)?;

        Ok(result)
    }
}
