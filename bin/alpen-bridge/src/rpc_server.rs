//! Bootstraps an RPC server for the operator.

use std::{fmt, sync::Arc};

use anyhow::{bail, Context};
use async_trait::async_trait;
use bitcoin::{taproot::Signature, OutPoint, PublicKey, Txid};
use chrono::{DateTime, Utc};
use duty_tracker::contract_state_machine::{ContractCfg, ContractState, MachineState};
use jsonrpsee::{
    core::RpcResult,
    types::{ErrorCode, ErrorObjectOwned},
    RpcModule,
};
use libp2p::{identity::PublicKey as LibP2pPublicKey, PeerId};
use musig2::KeyAggContext;
use secp256k1::Parity;
use serde::Serialize;
use sqlx::{query_as, FromRow};
use strata_bridge_connectors::prelude::{ConnectorC1, ConnectorC1Path};
use strata_bridge_db::{
    errors::DbError,
    persistent::{
        errors::StorageError,
        sqlite::{execute_with_retries, SqliteDb},
    },
};
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_rpc::{
    traits::{
        StrataBridgeControlApiServer, StrataBridgeDaApiServer, StrataBridgeMonitoringApiServer,
    },
    types::{
        ChallengeStep, RpcBridgeDutyStatus, RpcClaimInfo, RpcDepositInfo, RpcDepositStatus,
        RpcDisproveData, RpcOperatorStatus, RpcReimbursementStatus, RpcWithdrawalInfo,
        RpcWithdrawalStatus,
    },
};
use strata_bridge_stake_chain::prelude::STAKE_VOUT;
use strata_bridge_tx_graph::transactions::{
    claim::CHALLENGE_VOUT,
    deposit::DepositTx,
    prelude::{ChallengeTx, ChallengeTxInput},
};
use strata_p2p::swarm::handle::P2PHandle;
use strata_primitives::buf::Buf32;
use tokio::{
    sync::{oneshot, RwLock},
    time::interval,
};
use tracing::{debug, error, info, warn};

use crate::{config::RpcConfig, constants::DEFAULT_RPC_CACHE_REFRESH_INTERVAL, params::Params};

/// Starts an RPC server for a bridge operator.
pub(crate) async fn start_rpc<T>(rpc_impl: &T, rpc_addr: &str) -> anyhow::Result<()>
where
    T: StrataBridgeControlApiServer
        + StrataBridgeMonitoringApiServer
        + StrataBridgeDaApiServer
        + Clone
        + Sync
        + Send,
{
    let mut rpc_module = RpcModule::new(rpc_impl.clone());

    let control_api = StrataBridgeControlApiServer::into_rpc(rpc_impl.clone());
    let monitoring_api = StrataBridgeMonitoringApiServer::into_rpc(rpc_impl.clone());
    let da_api = StrataBridgeDaApiServer::into_rpc(rpc_impl.clone());

    rpc_module.merge(control_api).context("merge control api")?;
    rpc_module
        .merge(monitoring_api)
        .context("merge monitoring api")?;
    rpc_module.merge(da_api).context("merge da api")?;

    info!("starting bridge rpc server at {rpc_addr}");
    let rpc_server = jsonrpsee::server::ServerBuilder::new()
        .build(&rpc_addr)
        .await
        .expect("build bridge rpc server");

    let rpc_handle = rpc_server.start(rpc_module);

    // Using `_` for `_stop_tx` as the variable causes it to be dropped immediately!
    // NOTE: The `_stop_tx` should be used by the shutdown manager (see the `strata-tasks` crate).
    // At the moment, the impl below just stops the client from stopping.
    let (_stop_tx, stop_rx): (oneshot::Sender<bool>, oneshot::Receiver<bool>) = oneshot::channel();
    debug!("bridge rpc server started");

    let _ = stop_rx.await;
    info!("stopping rpc server");

    if rpc_handle.stop().is_err() {
        warn!("rpc server already stopped");
    }

    Ok(())
}

/// In-memory representation of contract records from the database.
#[derive(Debug, Clone, FromRow)]
pub(crate) struct ContractRecord {
    /// The deposit transaction ID with respect to this contract.
    #[sqlx(rename = "deposit_txid")]
    pub(crate) deposit_txid: String,

    /// The deposit index with respect to this contract.
    #[sqlx(rename = "deposit_idx")]
    pub(crate) deposit_idx: i64,

    /// The deposit transaction with respect to this contract.
    #[sqlx(rename = "deposit_tx")]
    pub(crate) deposit_tx: Vec<u8>,

    /// The operator table that was in place when this contract was created.
    #[sqlx(rename = "operator_table")]
    pub(crate) operator_table: Vec<u8>,

    /// The latest state of the contract.
    #[sqlx(rename = "state")]
    pub(crate) state: String,
}

impl ContractRecord {
    /// Converts this record into a strongly-typed in-memory representation.
    fn into_typed(self) -> anyhow::Result<TypedContractRecord> {
        let deposit_txid = self.deposit_txid.parse::<Txid>().map_err(|e| {
            error!(?e, "Failed to parse deposit_txid");
            anyhow::anyhow!("Failed to parse deposit_txid: {e}")
        })?;
        let deposit_tx = bincode::deserialize(&self.deposit_tx).map_err(|e| {
            error!(?e, "Failed to deserialize deposit_tx");
            anyhow::anyhow!("Failed to deserialize deposit_tx: {e}")
        })?;
        let deposit_idx = self.deposit_idx as u32;
        let operator_table = bincode::deserialize(&self.operator_table).map_err(|e| {
            error!(?e, "Failed to deserialize operator_table");
            anyhow::anyhow!("Failed to deserialize operator_table: {e}")
        })?;
        let state = serde_json::from_str(&self.state).map_err(|e| {
            error!(?e, "Failed to deserialize state");
            anyhow::anyhow!("Failed to deserialize state: {e}")
        })?;

        Ok(TypedContractRecord {
            deposit_txid,
            deposit_idx,
            deposit_tx,
            operator_table,
            state,
        })
    }
}

/// Strongly-typed in-memory representation of contract records from the database.
#[derive(Debug, Clone)]
pub(crate) struct TypedContractRecord {
    /// The deposit transaction ID with respect to this contract.
    pub(crate) deposit_txid: Txid,

    /// The deposit index with respect to this contract.
    pub(crate) deposit_idx: u32,

    /// The deposit transaction with respect to this contract.
    pub(crate) deposit_tx: DepositTx,

    /// The operator table that was in place when this contract was created.
    pub(crate) operator_table: OperatorTable,

    /// The latest state of the contract.
    pub(crate) state: MachineState,
}

/// RPC server for the bridge node.
/// Holds a handle to the database and the P2P messages; and a copy of [`Params`].
#[derive(Clone)]
pub(crate) struct BridgeRpc {
    /// Node start time.
    start_time: DateTime<Utc>,

    /// Database handle.
    db: SqliteDb,

    /// Cached contracts from the database, refreshed periodically.
    ///
    /// This comprises of:
    ///
    /// 1. `TypesContractRecord`: the contract record with its associated types.
    /// 2. `ContractCfg`: information that remain static for the lifetime of the contract.
    cached_contracts: Arc<RwLock<Vec<(TypedContractRecord, ContractCfg)>>>,

    /// P2P message handle.
    ///
    /// # Warning
    ///
    /// The bridge RPC server should *NEVER* call [`P2PHandle::next_event`] as it will mess with
    /// the duty tracker processing of messages in the P2P gossip network.
    ///
    /// The same applies for the `Stream` implementation of [`P2PHandle`].
    p2p_handle: P2PHandle,

    /// Consensus-critical parameters that dictate the behavior of the bridge node.
    params: Params,

    /// RPC server configuration.
    config: RpcConfig,
}

impl BridgeRpc {
    /// Create a new instance of [`BridgeRpc`].
    pub(crate) fn new(
        db: SqliteDb,
        p2p_handle: P2PHandle,
        params: Params,
        config: RpcConfig,
    ) -> Self {
        // Initialize with empty cache
        let cached_contracts = Arc::new(RwLock::new(Vec::new()));
        let start_time = Utc::now();

        let instance = Self {
            start_time,
            db,
            cached_contracts,
            p2p_handle,
            params,
            config,
        };

        // Start the cache refresh task
        instance.start_cache_refresh_task();

        instance
    }

    /// Starts a task to periodically refresh the contracts cache.
    fn start_cache_refresh_task(&self) {
        let db = self.db.clone();
        let cached_contracts = self.cached_contracts.clone();
        let db_config = *self.db.config();

        // Clone the params we need before spawning the task
        let network = self.params.network;
        let connectors = self.params.connectors;
        let tx_graph = self.params.tx_graph;
        let sidesystem = self.params.sidesystem.clone();
        let stake_chain = self.params.stake_chain;

        let period = self
            .config
            .refresh_interval
            .unwrap_or(DEFAULT_RPC_CACHE_REFRESH_INTERVAL);

        // Spawn a background task to refresh the cache
        tokio::spawn(async move {
            info!(?period, "initializing rpc server cache refresh task");

            // Initial cache fill
            let contracts = match execute_with_retries(&db_config, || async {
                let result: Result<Vec<ContractRecord>, _> = query_as!(
                    ContractRecord,
                    r#"
                    SELECT
                        deposit_txid,
                        deposit_idx,
                        deposit_tx,
                        operator_table,
                        state
                    FROM contracts
                    "#,
                )
                .fetch_all(db.pool())
                .await;

                result.map_err(|e| DbError::Storage(StorageError::Driver(e)))
            })
            .await
            {
                Ok(contracts) => contracts,
                Err(err) => {
                    error!(?err, "failed to initialize contracts cache");
                    Vec::new() // Return empty vector on error
                }
            };

            info!("initializing rpc server contract cache");
            // Convert raw records to typed records
            let refreshed_contracts: Vec<_> = contracts
                .into_iter()
                .filter_map(|record| record.into_typed().ok())
                .map(|record| {
                    let config = ContractCfg {
                        network,
                        operator_table: record.operator_table.clone(),
                        connector_params: connectors,
                        peg_out_graph_params: tx_graph,
                        sidesystem_params: sidesystem.clone(),
                        stake_chain_params: stake_chain,
                        deposit_idx: record.deposit_idx,
                        deposit_tx: record.deposit_tx.clone(),
                    };
                    (record, config)
                })
                .collect();
            let num_contracts = refreshed_contracts.len();

            let mut cache_lock = cached_contracts.write().await;
            *cache_lock = refreshed_contracts;
            // Strive to always drop the lock as soon as possible to avoid blocking other
            // tasks.
            drop(cache_lock);
            debug!(%num_contracts, "rpc server contracts cache initialized");

            // Periodic refresh in a separate loop outside the closure
            let mut refresh_interval = interval(period);
            loop {
                refresh_interval.tick().await;

                // Each refresh uses execute_with_retries only for the DB operation
                let contracts = match execute_with_retries(&db_config, || async {
                    let result: Result<Vec<ContractRecord>, _> = query_as!(
                        ContractRecord,
                        r#"
                                SELECT
                                    deposit_txid,
                                    deposit_idx,
                                    deposit_tx,
                                    operator_table,
                                    state
                                FROM contracts
                                "#,
                    )
                    .fetch_all(db.pool())
                    .await;

                    result.map_err(|e| DbError::Storage(StorageError::Driver(e)))
                })
                .await
                {
                    Ok(contracts) => contracts,
                    Err(err) => {
                        error!(?err, "failed to refresh contracts cache");
                        Vec::new() // Return empty vector on error
                    }
                };

                let num_contracts_before = contracts.len();
                info!(%num_contracts_before, "refreshing rpc server contract cache");

                // Convert raw records to typed records
                let refreshed_contracts: Vec<_> = contracts
                    .into_iter()
                    .filter_map(|record| record.into_typed().ok())
                    .map(|record| {
                        let config = ContractCfg {
                            network,
                            operator_table: record.operator_table.clone(),
                            connector_params: connectors,
                            peg_out_graph_params: tx_graph,
                            sidesystem_params: sidesystem.clone(),
                            stake_chain_params: stake_chain,
                            deposit_idx: record.deposit_idx,
                            deposit_tx: record.deposit_tx.clone(),
                        };
                        (record, config)
                    })
                    .collect();
                let num_contracts_after = refreshed_contracts.len();

                let mut cache_lock = cached_contracts.write().await;
                *cache_lock = refreshed_contracts;
                // Strive to always drop the lock as soon as possible to avoid blocking
                // other tasks.
                drop(cache_lock);
                debug!(%num_contracts_after, "contracts cache refreshed");
            }
        });
    }
}

#[async_trait]
impl StrataBridgeControlApiServer for BridgeRpc {
    async fn get_uptime(&self) -> RpcResult<u64> {
        let current_time = Utc::now().timestamp();
        let start_time = self.start_time.timestamp();

        // The user might care about their system time being incorrect.
        if current_time <= start_time {
            return Err(rpc_error(
                ErrorCode::InternalError,
                "system time may be inaccurate", // `start_time` may have been incorrect too
                current_time.saturating_sub(start_time),
            ));
        }

        Ok(current_time.abs_diff(start_time))
    }
}

#[async_trait]
impl StrataBridgeMonitoringApiServer for BridgeRpc {
    async fn get_bridge_operators(&self) -> RpcResult<Vec<PublicKey>> {
        Ok(self
            .params
            .keys
            .musig2
            .iter()
            .map(|x_only_pk| {
                let secp_pk = x_only_pk.public_key(Parity::Even);
                PublicKey::from(secp_pk)
            })
            .collect())
    }

    async fn get_operator_status(&self, operator_pk: PublicKey) -> RpcResult<RpcOperatorStatus> {
        let conversion = convert_operator_pk_to_peer_id(&self.params, &operator_pk);
        // Avoid DoS attacks by just returning an error if the public key is invalid
        if conversion.is_err() {
            return Err(rpc_error(
                ErrorCode::InvalidRequest,
                "Invalid operator public key",
                operator_pk,
            ));
        }
        // NOTE: safe to unwrap because we just checked if it's valid
        if self.p2p_handle.is_connected(conversion.unwrap()).await {
            Ok(RpcOperatorStatus::Online)
        } else {
            Ok(RpcOperatorStatus::Offline)
        }
    }

    async fn get_deposit_requests(&self) -> RpcResult<Vec<Txid>> {
        let cached_contracts = self.cached_contracts.read().await;

        let deposit_requests = cached_contracts
            .iter()
            .map(|entry| entry.1.deposit_request_txid())
            .collect();

        Ok(deposit_requests)
    }

    async fn get_deposit_request_info(
        &self,
        deposit_request_txid: Txid,
    ) -> RpcResult<RpcDepositInfo> {
        let cached_contracts = self.cached_contracts.read().await;

        for entry in cached_contracts.iter() {
            let entry_deposit_request_txid = entry.1.deposit_request_txid();
            if deposit_request_txid == entry_deposit_request_txid {
                let status = match &entry.0.state.state {
                    ContractState::Requested { .. } => RpcDepositStatus::InProgress,
                    _ => RpcDepositStatus::Complete {
                        deposit_txid: entry.0.deposit_txid,
                    },
                };

                return Ok(RpcDepositInfo {
                    status,
                    deposit_request_txid,
                });
            }
        }

        Err(rpc_error(
            ErrorCode::InvalidRequest,
            "Deposit request transaction ID not found",
            deposit_request_txid,
        ))
    }

    async fn get_bridge_duties(&self) -> RpcResult<Vec<RpcBridgeDutyStatus>> {
        let cached_contracts = self.cached_contracts.read().await;

        let duties = cached_contracts
            .iter()
            .filter_map(|entry| {
                match entry.0.state.state {
                    ContractState::Requested { .. } => Some(RpcBridgeDutyStatus::Deposit {
                        deposit_request_txid: entry.1.deposit_request_txid(),
                    }),
                    ContractState::Assigned {
                        withdrawal_request_txid,
                        fulfiller,
                        ..
                    } => Some(RpcBridgeDutyStatus::Withdrawal {
                        withdrawal_request_txid,
                        assigned_operator_idx: fulfiller,
                    }),
                    // Anything else is not a duty for the bridge operator
                    _ => None,
                }
            })
            .collect();

        Ok(duties)
    }

    async fn get_bridge_duties_by_operator_pk(
        &self,
        operator_pk: PublicKey,
    ) -> RpcResult<Vec<RpcBridgeDutyStatus>> {
        let cached_contracts = self.cached_contracts.read().await;

        // NOTE: duties by operator pk is only for withdrawal duties,
        //       it does not make sense for deposit duties
        let duties = cached_contracts
            .iter()
            .filter_map(|entry| {
                // Get the operator p2p key from the operator table
                // If the key does not exist, just ignore that entry and continue
                // as we want to extract all relevant duties for a given operator
                // and there may be other duties in subsequent entries that the caller cares about.
                let operator_p2p_pk = entry
                    .0
                    .operator_table
                    .btc_key_to_p2p_key(&operator_pk.inner)?;

                // Then, only get the entries where the operator index matches
                match &entry.0.state.state {
                    ContractState::Assigned {
                        claim_txids,
                        withdrawal_request_txid,
                        fulfiller,
                        ..
                    } if claim_txids.contains_key(operator_p2p_pk) => {
                        Some(RpcBridgeDutyStatus::Withdrawal {
                            withdrawal_request_txid: *withdrawal_request_txid,
                            assigned_operator_idx: *fulfiller,
                        })
                    }
                    _ => None,
                }
            })
            .collect();

        Ok(duties)
    }

    async fn get_withdrawals(&self) -> RpcResult<Vec<Buf32>> {
        let cached_contracts = self.cached_contracts.read().await;

        let mut withdrawals = Vec::new();
        for entry in cached_contracts.iter() {
            // NOTE: this is a source of bugs, don't use the `_` to match all.
            match &entry.0.state.state {
                ContractState::Assigned {
                    withdrawal_request_txid,
                    ..
                }
                | ContractState::Fulfilled {
                    withdrawal_request_txid,
                    ..
                }
                | ContractState::Claimed {
                    withdrawal_request_txid,
                    ..
                }
                | ContractState::Challenged {
                    withdrawal_request_txid,
                    ..
                }
                | ContractState::PreAssertConfirmed {
                    withdrawal_request_txid,
                    ..
                }
                | ContractState::AssertDataConfirmed {
                    withdrawal_request_txid,
                    ..
                }
                | ContractState::Asserted {
                    withdrawal_request_txid,
                    ..
                }
                | ContractState::Resolved {
                    withdrawal_request_txid,
                    ..
                } => {
                    withdrawals.push(*withdrawal_request_txid);
                }

                ContractState::Requested { .. }
                | ContractState::Deposited { .. }
                | ContractState::Disproved { .. }
                | ContractState::Aborted => {
                    continue;
                }
            }
        }

        Ok(withdrawals)
    }

    async fn get_withdrawal_info(
        &self,
        withdrawal_request_txid: Buf32,
    ) -> RpcResult<Option<RpcWithdrawalInfo>> {
        let cached_contracts = self.cached_contracts.read().await;

        // Find the contract with the matching withdrawal_request_txid
        let withdrawal_info =
            cached_contracts
                .iter()
                .find_map(|entry| match &entry.0.state.state {
                    // NOTE: this is a source of bugs, don't use the `_` to match all.

                    // No withdraw information.
                    ContractState::Requested { .. }
                    | ContractState::Deposited { .. }
                    | ContractState::Disproved { .. }
                    | ContractState::Aborted => {
                        // These states do not have withdrawals, so we skip them
                        None
                    }

                    // Withdraw is in progress.
                    ContractState::Assigned {
                        withdrawal_request_txid: entry_withdrawal_request_txid,
                        ..
                    } => {
                        if withdrawal_request_txid == *entry_withdrawal_request_txid {
                            Some(RpcWithdrawalInfo {
                                status: RpcWithdrawalStatus::InProgress,
                                withdrawal_request_txid,
                            })
                        } else {
                            None
                        }
                    }

                    ContractState::Fulfilled {
                        withdrawal_request_txid: entry_withdrawal_request_txid,
                        withdrawal_fulfillment_txid,
                        ..
                    }
                    | ContractState::Claimed {
                        withdrawal_request_txid: entry_withdrawal_request_txid,
                        withdrawal_fulfillment_txid,
                        ..
                    }
                    | ContractState::Challenged {
                        withdrawal_request_txid: entry_withdrawal_request_txid,
                        withdrawal_fulfillment_txid,
                        ..
                    }
                    | ContractState::PreAssertConfirmed {
                        withdrawal_request_txid: entry_withdrawal_request_txid,
                        withdrawal_fulfillment_txid,
                        ..
                    }
                    | ContractState::AssertDataConfirmed {
                        withdrawal_request_txid: entry_withdrawal_request_txid,
                        withdrawal_fulfillment_txid,
                        ..
                    }
                    | ContractState::Asserted {
                        withdrawal_request_txid: entry_withdrawal_request_txid,
                        withdrawal_fulfillment_txid,
                        ..
                    }
                    | ContractState::Resolved {
                        withdrawal_request_txid: entry_withdrawal_request_txid,
                        withdrawal_fulfillment_txid,
                        ..
                    } => {
                        if withdrawal_request_txid == *entry_withdrawal_request_txid {
                            Some(RpcWithdrawalInfo {
                                status: RpcWithdrawalStatus::Complete {
                                    fulfillment_txid: *withdrawal_fulfillment_txid,
                                },
                                withdrawal_request_txid,
                            })
                        } else {
                            None
                        }
                    }
                });

        Ok(withdrawal_info)
    }

    async fn get_claims(&self) -> RpcResult<Vec<Txid>> {
        let cached_contracts = self.cached_contracts.read().await;

        let claims: Vec<_> = cached_contracts
            .iter()
            .filter_map(|entry| match &entry.0.state.state {
                // States that have an active graph with a claim transaction.
                ContractState::Claimed { active_graph, .. }
                | ContractState::Challenged { active_graph, .. }
                | ContractState::PreAssertConfirmed { active_graph, .. }
                | ContractState::AssertDataConfirmed { active_graph, .. }
                | ContractState::Asserted { active_graph, .. }
                | ContractState::Fulfilled { active_graph, .. } => Some(active_graph.1.claim_txid),

                // States that do not have an active graph with a claim transaction.
                ContractState::Requested { .. }
                | ContractState::Deposited { .. }
                | ContractState::Assigned { .. } => None,

                // States that are terminal and do not have an active graph.
                ContractState::Disproved { .. } | ContractState::Aborted => None,

                // However resolved contracts have a definite `claim_txid`.
                ContractState::Resolved { claim_txid, .. } => Some(*claim_txid),
            })
            .collect();

        Ok(claims)
    }

    async fn get_claim_info(&self, claim_txid: Txid) -> RpcResult<Option<RpcClaimInfo>> {
        let cached_contracts = self.cached_contracts.read().await;

        let claim_info = cached_contracts
            .iter()
            .find(|entry| {
                let claim_txids = entry.0.state.state.claim_txids();

                claim_txids.contains(&claim_txid)
            })
            .map(|entry| contract_state_to_reimbursement_status(&entry.0.state.state))
            .map(|status| RpcClaimInfo { claim_txid, status });

        Ok(claim_info)
    }
}

/// Helper function to convert a [`ContractState`] to a [`RpcReimbursementStatus`].
const fn contract_state_to_reimbursement_status(state: &ContractState) -> RpcReimbursementStatus {
    match state {
        ContractState::Requested { .. }
        | ContractState::Deposited { .. }
        | ContractState::Assigned { .. }
        | ContractState::Fulfilled { .. }
        | ContractState::Aborted => RpcReimbursementStatus::NotStarted,
        ContractState::Claimed { .. } => RpcReimbursementStatus::InProgress {
            challenge_step: ChallengeStep::Claim,
        },
        ContractState::Challenged { .. } => RpcReimbursementStatus::Challenged {
            challenge_step: ChallengeStep::Challenge,
        },
        ContractState::PreAssertConfirmed { .. }
        | ContractState::AssertDataConfirmed { .. }
        | ContractState::Asserted { .. } => RpcReimbursementStatus::Challenged {
            challenge_step: ChallengeStep::Assert,
        },
        ContractState::Resolved { payout_txid, .. } => RpcReimbursementStatus::Complete {
            payout_txid: *payout_txid,
        },
        ContractState::Disproved { .. } => RpcReimbursementStatus::Cancelled,
    }
}

#[async_trait]
impl StrataBridgeDaApiServer for BridgeRpc {
    async fn get_challenge_tx(&self, claim_txid: Txid) -> RpcResult<Option<bitcoin::Transaction>> {
        debug!(%claim_txid, "getting challenge transaction");

        let contracts = self.cached_contracts.read().await;
        let challenge_tx = contracts
            .iter()
            .find_map(|contract| {
                let challenge_sig = contract
                    .0
                    .state
                    .state
                    .graph_sigs()
                    .get(&claim_txid)
                    .map(|sigs| sigs.challenge);

                let reimbursement_key = contract
                    .0
                    .state
                    .state
                    .graph_input(claim_txid)
                    .map(|input| input.operator_pubkey);

                match (challenge_sig, reimbursement_key) {
                    (Some(challenge_sig), Some(reimbursement_key)) => {
                        Some((challenge_sig, reimbursement_key))
                    }
                    _ => None, // No challenge transaction available for this claim
                }
            })
            .map(|(challenge_sig, reimbursement_key)| {
                let challenge_input = ChallengeTxInput {
                    claim_outpoint: OutPoint::new(claim_txid, CHALLENGE_VOUT),
                    challenge_amt: self.params.tx_graph.challenge_cost,
                    operator_pubkey: reimbursement_key,
                    network: self.params.network,
                };

                let key_agg_ctx = KeyAggContext::new(
                    self.params
                        .keys
                        .musig2
                        .iter()
                        .map(|x_only| x_only.public_key(Parity::Even)),
                )
                .expect("key aggregation must succeed");
                let agg_pubkey = key_agg_ctx.aggregated_pubkey();

                let challenge_connector = ConnectorC1::new(
                    agg_pubkey,
                    self.params.network,
                    self.params.connectors.payout_optimistic_timelock,
                );

                ChallengeTx::new(challenge_input, challenge_connector)
                    .finalize_presigned(ConnectorC1Path::Challenge(challenge_sig))
            });

        Ok(challenge_tx)
    }

    async fn get_challenge_signature(&self, claim_txid: Txid) -> RpcResult<Option<Signature>> {
        debug!(%claim_txid, "getting challenge signature");

        let contracts = self.cached_contracts.read().await;

        Ok(contracts.iter().find_map(|contract| {
            contract
                .0
                .state
                .state
                .graph_sigs()
                .get(&claim_txid)
                .map(|sigs| sigs.challenge)
        }))
    }

    async fn get_disprove_data(&self, claim_txid: Txid) -> RpcResult<Option<RpcDisproveData>> {
        debug!(%claim_txid, "getting disprove data");

        let contracts = self.cached_contracts.read().await;

        let disprove_data = contracts
            .iter()
            .find(|contract| contract.0.state.state.claim_txids().contains(&claim_txid))
            .iter()
            .find_map(|contract| {
                let state = &contract.0.state.state;
                let graph_input = state.graph_input(claim_txid)?;
                let graph_summary = state.graph_summary(claim_txid)?;
                let n_of_n_sig = state.graph_sigs().get(&claim_txid)?.disprove;

                Some(RpcDisproveData {
                    post_assert_txid: graph_summary.post_assert_txid,
                    deposit_txid: contract.0.deposit_txid,
                    stake_outpoint: OutPoint::new(graph_summary.stake_txid, STAKE_VOUT),
                    stake_hash: graph_input.stake_hash,
                    operator_pubkey: graph_input.operator_pubkey,
                    wots_public_keys: graph_input.wots_public_keys.clone(),
                    n_of_n_sig,
                })
            });

        Ok(disprove_data)
    }
}

/// Converts a *MuSig2* operator [`PublicKey`] to a *P2P* [`PeerId`].
///
/// Internally checks if the operator MuSig2 [`PublicKey`] is present in the vector of operator
/// MuSig2 public keys in the [`Params`], then fetches the corresponding P2P [`PublicKey`] in the
/// vector of the P2P public keys in the [`Params`] assuming that the index is the same in both
/// vectors.
pub(crate) fn convert_operator_pk_to_peer_id(
    params: &Params,
    operator_pk: &PublicKey,
) -> anyhow::Result<PeerId> {
    let operator_index = params
        .keys
        .musig2
        .iter()
        .position(|pk| *pk == operator_pk.inner.x_only_public_key().0);
    if let Some(index) = operator_index {
        let pk: LibP2pPublicKey = params.keys.p2p[index].clone().into();
        Ok(PeerId::from(pk))
    } else {
        bail!("Could not find operator public key in params")
    }
}

/// Returns an [`ErrorObjectOwned`] with the given code, message, and data.
/// Useful for creating custom error objects in RPC responses.
fn rpc_error<T: fmt::Display + Serialize>(
    err_code: ErrorCode,
    message: &str,
    data: T,
) -> ErrorObjectOwned {
    ErrorObjectOwned::owned::<_>(err_code.code(), message, Some(data))
}
