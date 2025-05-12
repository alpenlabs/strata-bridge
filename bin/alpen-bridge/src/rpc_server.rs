//! Bootstraps an RPC server for the operator.

use std::{fmt, sync::Arc, time::Duration};

use anyhow::{bail, Context};
use async_trait::async_trait;
use bitcoin::{taproot::Signature, OutPoint, PublicKey, Txid};
use chrono::{DateTime, Utc};
use duty_tracker::contract_state_machine::{ContractCfg, ContractState};
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned, RpcModule};
use libp2p::{identity::PublicKey as LibP2pPublicKey, PeerId};
use secp256k1::Parity;
use serde::Serialize;
use sqlx::{query_as, FromRow};
use strata_bridge_db::persistent::sqlite::SqliteDb;
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_bridge_rpc::{
    traits::{
        StrataBridgeControlApiServer, StrataBridgeDaApiServer, StrataBridgeMonitoringApiServer,
    },
    types::{
        RpcBridgeDutyStatus, RpcClaimInfo, RpcDepositStatus, RpcOperatorStatus,
        RpcReimbursementStatus, RpcWithdrawalInfo, RpcWithdrawalStatus,
    },
};
use strata_bridge_tx_graph::transactions::deposit::DepositTx;
use strata_p2p::swarm::handle::P2PHandle;
use tokio::{
    sync::{oneshot, RwLock},
    time::interval,
};
use tracing::{debug, error, info, warn};

use crate::params::Params;

/// Starts an RPC server for a bridge operator.
pub(crate) async fn start_rpc<T>(rpc_impl: &T, rpc_addr: &str) -> anyhow::Result<()>
where
    T: StrataBridgeControlApiServer + Clone + Sync + Send,
{
    let mut rpc_module = RpcModule::new(rpc_impl.clone());

    let control_api = StrataBridgeControlApiServer::into_rpc(rpc_impl.clone());

    rpc_module.merge(control_api).context("merge control api")?;

    info!("Starting bridge RPC server at: {rpc_addr}");
    let rpc_server = jsonrpsee::server::ServerBuilder::new()
        .build(&rpc_addr)
        .await
        .expect("build bridge rpc server");

    let rpc_handle = rpc_server.start(rpc_module);
    // Using `_` for `_stop_tx` as the variable causes it to be dropped immediately!
    // NOTE: The `_stop_tx` should be used by the shutdown manager (see the `strata-tasks` crate).
    // At the moment, the impl below just stops the client from stopping.
    let (_stop_tx, stop_rx): (oneshot::Sender<bool>, oneshot::Receiver<bool>) = oneshot::channel();

    info!("bridge RPC server started at: {rpc_addr}");

    let _ = stop_rx.await;
    info!("stopping RPC server");

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

    /// The deposit transaction with respect to this contract.
    #[sqlx(rename = "deposit_tx")]
    pub(crate) deposit_tx: Vec<u8>,

    /// The deposit index with respect to this contract.
    #[sqlx(rename = "deposit_idx")]
    pub(crate) deposit_idx: i64,

    /// The operator table that was in place when this contract was created.
    #[sqlx(rename = "operator_table")]
    pub(crate) operator_table: Vec<u8>,

    /// The latest state of the contract.
    #[sqlx(rename = "state")]
    pub(crate) state: Vec<u8>,
}

impl ContractRecord {
    fn into_typed(self) -> anyhow::Result<TypedContractRecord> {
        Ok(TypedContractRecord {
            deposit_txid: self.deposit_txid.parse::<Txid>()?,
            deposit_tx: bincode::deserialize(&self.deposit_tx)?,
            deposit_idx: self.deposit_idx as u32,
            operator_table: bincode::deserialize(&self.operator_table)?,
            state: bincode::deserialize(&self.state)?,
        })
    }
}

#[derive(Debug, Clone)]
pub(crate) struct TypedContractRecord {
    pub(crate) deposit_txid: Txid,
    pub(crate) deposit_tx: DepositTx,
    pub(crate) deposit_idx: u32,
    pub(crate) operator_table: OperatorTable,
    pub(crate) state: ContractState,
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

    /// The consensus-critical parameters that dictate the behavior of the bridge node.
    params: Params,
}

impl BridgeRpc {
    /// Create a new instance of [`BridgeRpc`].
    pub(crate) fn new(db: SqliteDb, p2p_handle: P2PHandle, params: Params) -> Self {
        // Initialize with empty cache
        let cached_contracts = Arc::new(RwLock::new(Vec::new()));
        let instance = Self {
            start_time: Utc::now(),
            db,
            cached_contracts,
            p2p_handle,
            params,
        };

        // Start the cache refresh task
        instance.start_cache_refresh_task();

        instance
    }

    /// Starts a task to periodically refresh the contracts cache.
    fn start_cache_refresh_task(&self) {
        let db = self.db.clone();
        let cached_contracts = self.cached_contracts.clone();
        // Clone the params we need before spawning the task
        let network = self.params.network;
        let connectors = self.params.connectors;
        let tx_graph = self.params.tx_graph.clone();
        let sidesystem = self.params.sidesystem.clone();
        let stake_chain = self.params.stake_chain;

        // Spawn a background task to refresh the cache
        tokio::spawn(async move {
            // TODO(@storopoli): make this configurable
            let mut interval = interval(Duration::from_secs(10 * 60)); // 10 minutes, i.e. a bitcoin block

            // Initial cache fill
            if let Ok(contracts) = query_as!(
                ContractRecord,
                r#"SELECT deposit_txid as "deposit_txid!", deposit_tx as "deposit_tx!", deposit_idx as "deposit_idx!", operator_table as "operator_table!", state as "state!" FROM contracts"#
            )
            .fetch_all(db.pool())
            .await
            {
                let mut cache_lock = cached_contracts.write().await;
                // Convert raw records to typed records
                *cache_lock = contracts
                    .into_iter()
                    .filter_map(|record| record.into_typed().ok())
                    .map(|record| {
                        let config = ContractCfg {
                            network,
                            operator_table: record.operator_table.clone(),
                            connector_params: connectors,
                            peg_out_graph_params: tx_graph.clone(),
                            sidesystem_params: sidesystem.clone(),
                            stake_chain_params: stake_chain,
                            deposit_idx: record.deposit_idx,
                            deposit_tx: record.deposit_tx.clone(),
                        };
                        (record, config)
                    })
                    .collect();
                info!(cache_len=%cache_lock.len(), "Contracts cache initialized");

                // drop the lock!
                drop(cache_lock);
            } else {
                error!("Failed to initialize contracts cache");
            }

            // Periodic refresh
            loop {
                interval.tick().await;

                match query_as!(
                    ContractRecord,
                    r#"SELECT deposit_txid as "deposit_txid!", deposit_tx as "deposit_tx!", deposit_idx as "deposit_idx!", operator_table as "operator_table!", state as "state!" FROM contracts"#
                )
                .fetch_all(db.pool())
                .await
                {
                    Ok(contracts) => {
                        let mut cache_lock = cached_contracts.write().await;
                        // Convert raw records to typed records
                        *cache_lock = contracts
                            .into_iter()
                            .filter_map(|record| record.into_typed().ok())
                            .map(|record| {
                                let config = ContractCfg {
                                    network,
                                    operator_table: record.operator_table.clone(),
                                    connector_params: connectors,
                                    peg_out_graph_params: tx_graph.clone(),
                                    sidesystem_params: sidesystem.clone(),
                                    stake_chain_params: stake_chain,
                                    deposit_idx: record.deposit_idx,
                                    deposit_tx: record.deposit_tx.clone(),
                                };
                                (record, config)
                            })
                            .collect();
                        debug!(cache_len=%cache_lock.len(), "Contracts cache refreshed");

                        // drop the lock!
                        drop(cache_lock);
                    }
                    Err(e) => {
                        error!(?e, "Failed to refresh contracts cache");
                    }
                }
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
                -32_000,
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
                -32001,
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

    async fn get_deposit_request_info(
        &self,
        deposit_request_outpoint: OutPoint,
    ) -> RpcResult<RpcDepositStatus> {
        let deposit_request_txid = deposit_request_outpoint.txid;
        // Use the cached contracts
        let all_entries = self.cached_contracts.read().await.clone();

        for entry in all_entries {
            let entry_deposit_request_txid = entry.1.deposit_request_txid();
            if deposit_request_txid == entry_deposit_request_txid {
                match &entry.0.state {
                    ContractState::Requested { .. } => {
                        return Ok(RpcDepositStatus::InProgress {
                            deposit_request_txid,
                        });
                    }
                    _ => {
                        return Ok(RpcDepositStatus::Complete {
                            deposit_request_txid,
                            deposit_txid: entry.0.deposit_txid,
                        });
                    }
                }
            }
        }

        Err(rpc_error(
            -32_001,
            "Deposit request outpoint not found",
            deposit_request_outpoint,
        ))
    }

    async fn get_bridge_duties(&self) -> RpcResult<Vec<RpcBridgeDutyStatus>> {
        // we don't care about the hot state here, we only care about the database
        let all_entries = self.cached_contracts.read().await.clone();

        let mut duties = Vec::new();
        for entry in all_entries {
            match &entry.0.state {
                ContractState::Requested { .. } => {
                    duties.push(RpcBridgeDutyStatus::Deposit {
                        deposit_request_txid: entry.1.deposit_request_txid(),
                    });
                }
                ContractState::Deposited { .. } => duties.push(RpcBridgeDutyStatus::Deposit {
                    deposit_request_txid: entry.1.deposit_request_txid(),
                }),
                ContractState::Assigned {
                    withdrawal_request_txid,
                    fulfiller,
                    ..
                } => duties.push(RpcBridgeDutyStatus::Withdrawal {
                    withdrawal_request_txid: *withdrawal_request_txid,
                    assigned_operator_idx: *fulfiller,
                }),
                ContractState::StakeTxReady {
                    withdrawal_request_txid,
                    fulfiller,
                    ..
                } => duties.push(RpcBridgeDutyStatus::Withdrawal {
                    withdrawal_request_txid: *withdrawal_request_txid,
                    assigned_operator_idx: *fulfiller,
                }),
                // Anything else is not a duty for the RPC server
                _ => (),
            }
        }

        Ok(duties)
    }

    async fn get_bridge_duties_by_operator_pk(
        &self,
        operator_pk: PublicKey,
    ) -> RpcResult<Vec<RpcBridgeDutyStatus>> {
        // Use the cached contracts
        let all_entries = self.cached_contracts.read().await.clone();

        // NOTE: duties by operator pk is only for withdrawal duties,
        //       it does not make sense for deposit duties
        let mut duties = Vec::new();
        for entry in all_entries {
            // Get the operator index from the operator table
            let operator_index = entry
                .0
                .operator_table
                .btc_key_to_idx(&operator_pk.inner)
                .ok_or_else(|| {
                    rpc_error(
                        -32001,
                        "Operator public key not found in operator table",
                        operator_pk,
                    )
                })?;

            let operator_p2p_pk = entry
                .0
                .operator_table
                .idx_to_op_key(&operator_index)
                .expect("we just checked that the index is valid");

            // Then, only get the entries where the operator index matches
            match &entry.0.state {
                ContractState::Assigned {
                    claim_txids,
                    withdrawal_request_txid,
                    ..
                } => {
                    if claim_txids.contains_key(operator_p2p_pk) {
                        duties.push(RpcBridgeDutyStatus::Withdrawal {
                            withdrawal_request_txid: *withdrawal_request_txid,
                            assigned_operator_idx: operator_index,
                        });
                    }
                }
                ContractState::StakeTxReady {
                    claim_txids,
                    withdrawal_request_txid,
                    ..
                } => {
                    if claim_txids.contains_key(operator_p2p_pk) {
                        duties.push(RpcBridgeDutyStatus::Withdrawal {
                            withdrawal_request_txid: *withdrawal_request_txid,
                            assigned_operator_idx: operator_index,
                        });
                    }
                }
                ContractState::Fulfilled {
                    claim_txids,
                    withdrawal_fulfillment_txid,
                    ..
                } => {
                    if claim_txids.contains_key(operator_p2p_pk) {
                        duties.push(RpcBridgeDutyStatus::Withdrawal {
                            withdrawal_request_txid: *withdrawal_fulfillment_txid,
                            assigned_operator_idx: operator_index,
                        });
                    }
                }
                _ => (),
            }
        }
        Ok(duties)
    }

    async fn get_withdrawal_info(
        &self,
        withdrawal_outpoint: OutPoint,
    ) -> RpcResult<RpcWithdrawalInfo> {
        let withdrawal_txid = withdrawal_outpoint.txid;
        // Use the cached contracts
        let all_entries = self.cached_contracts.read().await.clone();

        // Iterate over all contract states to find the matching withdrawal
        for entry in all_entries {
            match &entry.0.state {
                ContractState::Requested { .. } => todo!(),
                ContractState::Deposited { .. } => todo!(),
                ContractState::Assigned { .. } => todo!(),
                ContractState::StakeTxReady { .. } => todo!(),
                ContractState::Fulfilled {
                    withdrawal_fulfillment_txid,
                    ..
                } => {
                    if withdrawal_txid == *withdrawal_fulfillment_txid {
                        return Ok(RpcWithdrawalInfo {
                            status: RpcWithdrawalStatus::Complete {
                                fulfillment_txid: withdrawal_txid,
                            },
                        });
                    }
                }
                ContractState::Claimed { .. } => todo!(),
                ContractState::Challenged { .. } => todo!(),
                ContractState::Asserted { .. } => todo!(),
                ContractState::Disproved { .. } => todo!(),
                ContractState::Resolved { .. } => todo!(),
            }
        }

        Err(rpc_error(
            -32_001,
            "Withdrawal outpoint not found",
            withdrawal_outpoint,
        ))
    }

    async fn get_claims(&self) -> RpcResult<Vec<Txid>> {
        // Use the cached contracts
        let all_entries = self.cached_contracts.read().await.clone();

        let mut claims = Vec::new();
        for entry in all_entries {
            match &entry.0.state {
                ContractState::Requested { claim_txids, .. } => {
                    claims.extend(claim_txids.values().copied().collect::<Vec<Txid>>())
                }
                ContractState::Deposited { claim_txids, .. } => {
                    claims.extend(claim_txids.values().copied().collect::<Vec<Txid>>())
                }
                ContractState::Assigned { claim_txids, .. } => {
                    claims.extend(claim_txids.values().copied().collect::<Vec<Txid>>())
                }
                ContractState::StakeTxReady { claim_txids, .. } => {
                    claims.extend(claim_txids.values().copied().collect::<Vec<Txid>>())
                }
                ContractState::Fulfilled { claim_txids, .. } => {
                    claims.extend(claim_txids.values().copied().collect::<Vec<Txid>>())
                }
                ContractState::Claimed { claim_txids, .. } => {
                    claims.extend(claim_txids.values().copied().collect::<Vec<Txid>>())
                }
                ContractState::Challenged { claim_txids, .. } => {
                    claims.extend(claim_txids.values().copied().collect::<Vec<Txid>>())
                }
                ContractState::Asserted { claim_txids, .. } => {
                    claims.extend(claim_txids.values().copied().collect::<Vec<Txid>>())
                }
                ContractState::Disproved {} => (),
                ContractState::Resolved {} => (),
            }
        }

        Ok(claims)
    }

    async fn get_claim_info(&self, claim_txid: Txid) -> RpcResult<RpcClaimInfo> {
        // Use the cached contracts
        let all_entries = self.cached_contracts.read().await.clone();

        for entry in all_entries {
            match &entry.0.state {
                ContractState::Requested { claim_txids, .. } => {
                    let claim_txids = claim_txids.values().copied().collect::<Vec<Txid>>();
                    if claim_txids.contains(&claim_txid) {
                        return Ok(RpcClaimInfo {
                            claim_txid,
                            status: RpcReimbursementStatus::InProgress,
                        });
                    }
                }
                ContractState::Deposited { claim_txids, .. } => {
                    let claim_txids = claim_txids.values().copied().collect::<Vec<Txid>>();

                    if claim_txids.contains(&claim_txid) {
                        return Ok(RpcClaimInfo {
                            claim_txid,
                            status: RpcReimbursementStatus::InProgress,
                        });
                    }
                }
                ContractState::Assigned { claim_txids, .. } => {
                    let claim_txids = claim_txids.values().copied().collect::<Vec<Txid>>();

                    if claim_txids.contains(&claim_txid) {
                        return Ok(RpcClaimInfo {
                            claim_txid,
                            status: RpcReimbursementStatus::InProgress,
                        });
                    }
                }
                ContractState::StakeTxReady { claim_txids, .. } => {
                    let claim_txids = claim_txids.values().copied().collect::<Vec<Txid>>();

                    if claim_txids.contains(&claim_txid) {
                        return Ok(RpcClaimInfo {
                            claim_txid,
                            status: RpcReimbursementStatus::InProgress,
                        });
                    }
                }
                ContractState::Fulfilled { claim_txids, .. } => {
                    let claim_txids = claim_txids.values().copied().collect::<Vec<Txid>>();

                    if claim_txids.contains(&claim_txid) {
                        return Ok(RpcClaimInfo {
                            claim_txid,

                            status: RpcReimbursementStatus::InProgress,
                        });
                    }
                }
                ContractState::Claimed { claim_txids, .. } => {
                    let claim_txids = claim_txids.values().copied().collect::<Vec<Txid>>();

                    if claim_txids.contains(&claim_txid) {
                        return Ok(RpcClaimInfo {
                            claim_txid,
                            status: RpcReimbursementStatus::InProgress,
                        });
                    }
                }
                ContractState::Challenged { claim_txids, .. } => {
                    let claim_txids = claim_txids.values().copied().collect::<Vec<Txid>>();

                    if claim_txids.contains(&claim_txid) {
                        return Ok(RpcClaimInfo {
                            claim_txid,
                            status: RpcReimbursementStatus::Challenged,
                        });
                    }
                }
                ContractState::Asserted { claim_txids, .. } => {
                    let claim_txids = claim_txids.values().copied().collect::<Vec<Txid>>();

                    if claim_txids.contains(&claim_txid) {
                        return Ok(RpcClaimInfo {
                            claim_txid,
                            status: RpcReimbursementStatus::Challenged,
                        });
                    }
                }
                ContractState::Disproved { .. } => (),
                ContractState::Resolved { .. } => (),
            };
        }

        Err(rpc_error(-32_001, "Claim not found", claim_txid))
    }
}

#[async_trait]
impl StrataBridgeDaApiServer for BridgeRpc {
    async fn get_challenge_signature(&self, claim_txid: Txid) -> RpcResult<Option<Signature>> {
        debug!(%claim_txid, "getting challenge signature");

        let contracts = self.cached_contracts.read().await;

        Ok(contracts.iter().find_map(|contract| {
            if contract.0.state.claim_txids().contains(&claim_txid) {
                contract
                    .0
                    .state
                    .graph_sigs()
                    .get(&claim_txid)
                    .map(|sigs| sigs.challenge)
            } else {
                None
            }
        }))
    }

    async fn get_disprove_signature(&self, claim_txid: Txid) -> RpcResult<Option<Signature>> {
        debug!(%claim_txid, "getting disprove signature");

        let contracts = self.cached_contracts.read().await;

        Ok(contracts.iter().find_map(|contract| {
            if contract.0.state.claim_txids().contains(&claim_txid) {
                contract
                    .0
                    .state
                    .graph_sigs()
                    .get(&claim_txid)
                    .map(|sigs| sigs.disprove)
            } else {
                None
            }
        }))
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
fn rpc_error<T: fmt::Display + Serialize>(code: i32, message: &str, data: T) -> ErrorObjectOwned {
    ErrorObjectOwned::owned::<_>(code, message, Some(data))
}
