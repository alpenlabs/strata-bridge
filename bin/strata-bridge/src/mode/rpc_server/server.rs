//! JSON-RPC server wiring and trait implementations for bridge operator APIs.

use std::{fmt, sync::Arc};

use anyhow::Context;
use async_trait::async_trait;
use bitcoin::PublicKey;
use chrono::{DateTime, Utc};
use jsonrpsee::{
    RpcModule,
    core::RpcResult,
    types::{ErrorCode, ErrorObjectOwned},
};
use libp2p::{
    PeerId,
    identity::{PublicKey as LibP2pPublicKey, ed25519::PublicKey as LibP2pEdPublicKey},
};
use serde::Serialize;
use strata_bridge_common::params::Params;
use strata_bridge_db::fdb::client::FdbClient;
use strata_bridge_orchestrator::{
    persister::Persister,
    sm_registry::{SMConfig, SMRegistry},
};
use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx};
use strata_bridge_rpc::{
    traits::{
        StrataBridgeControlApiServer, StrataBridgeDaApiServer, StrataBridgeMonitoringApiServer,
    },
    types::{
        RpcAggregateSignatures, RpcBridgeDutyStatus, RpcDepositInfo, RpcDepositStatus,
        RpcGraphData, RpcOperatorStakeInfo, RpcOperatorStatus, RpcPendingWithdrawalInfo,
        RpcReimbursementStatus, RpcStakeAggregateSignatures, RpcStakeData, RpcWithdrawalStatus,
    },
};
use strata_bridge_sm::deposit::state::DepositState;
use strata_p2p::swarm::handle::CommandHandle;
use strata_tasks::TaskExecutor;
use tokio::{
    sync::{RwLock, oneshot},
    time::interval,
};
use tracing::{debug, info, warn};

use super::monitoring::{
    active_claim_from_state, aggregate_signatures_response, bridge_duties_for_deposit,
    bridge_duties_for_operator_pk, get_pending_assigned_operator, get_reimbursement_operator,
    graph_data_response, reimbursement_status, stake_state_to_rpc, withdrawal_status,
};
use crate::{
    config::{Config, RpcConfig},
    constants::DEFAULT_RPC_CACHE_REFRESH_INTERVAL,
    mode::{
        rpc_server::da::{stake_aggregate_signatures_response, stake_data_response},
        services::orchestrator::build_sm_config,
    },
};

/// Starts an RPC server for a bridge operator.
pub(in crate::mode) async fn init_rpc_server(
    params: &Params,
    config: &Config,
    db: Arc<FdbClient>,
    command_handle: CommandHandle,
    executor: &TaskExecutor,
) -> anyhow::Result<()> {
    let rpc_persister = Persister::new(db);
    let sm_config = build_sm_config(config, params);

    let rpc_config = config.rpc.clone();
    let rpc_addr = rpc_config.rpc_addr.clone();
    let rpc_params = params.clone();

    executor.spawn_critical_async_with_shutdown("rpc_server", |_| async move {
        let rpc_impl = BridgeRpc::new(
            rpc_persister,
            command_handle,
            rpc_params,
            sm_config,
            rpc_config,
        );
        start_rpc(&rpc_impl, rpc_addr.as_str()).await
    });

    Ok(())
}

async fn start_rpc<T>(rpc_impl: &T, rpc_addr: &str) -> anyhow::Result<()>
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
    debug!("starting bridge rpc server at {rpc_addr}");
    let rpc_server = jsonrpsee::server::ServerBuilder::new()
        .build(&rpc_addr)
        .await
        .expect("build bridge rpc server");
    let rpc_handle = rpc_server.start(rpc_module);

    // Using `_` for `_stop_tx` as the variable causes it to be dropped immediately!
    // NOTE: (Rajil1213) The `_stop_tx` should be used by the shutdown manager (see the
    // `strata-tasks` crate). At the moment, the impl below just stops the client from stopping.
    let (_stop_tx, stop_rx): (oneshot::Sender<bool>, oneshot::Receiver<bool>) = oneshot::channel();
    let _ = stop_rx.await;
    info!("stopping rpc server");

    if rpc_handle.stop().is_err() {
        warn!("rpc server already stopped");
    }

    Ok(())
}

/// RPC server for the bridge node.
/// Holds a handle to the database and the P2P messages; and a copy of [`Params`].
#[derive(Clone)]
pub(crate) struct BridgeRpc {
    /// Node start time.
    start_time: DateTime<Utc>,

    /// Database handle.
    db: Persister,
    /// Cached registry of all state machines in the database, refreshed periodically.
    cached_registry: Arc<RwLock<SMRegistry>>,

    /// P2P message handle.
    ///
    /// # Warning
    ///
    /// The bridge RPC server should *NEVER* call [`CommandHandle::next_event`] as it will mess
    /// with the duty tracker processing of messages in the P2P gossip network.
    ///
    /// The same applies for the `Stream` implementation of [`CommandHandle`].
    command_handle: CommandHandle,

    /// Consensus-critical parameters that dictate the behavior of the bridge node.
    params: Params,

    /// RPC server configuration.
    config: RpcConfig,
}

impl BridgeRpc {
    /// Create a new instance of [`BridgeRpc`].
    pub(crate) fn new(
        db: Persister,
        command_handle: CommandHandle,
        params: Params,
        sm_config: SMConfig,
        config: RpcConfig,
    ) -> Self {
        // Initialize with empty cache
        let cached_contracts = Arc::new(RwLock::new(SMRegistry::new(sm_config)));
        let start_time = Utc::now();

        let instance = Self {
            start_time,
            db,
            cached_registry: cached_contracts,
            command_handle,
            params,
            config,
        };

        // Start the cache refresh task
        instance.start_cache_refresh_task();

        instance
    }

    /// Starts a task to periodically refresh the contracts cache.
    fn start_cache_refresh_task(&self) {
        let cached_registry = self.cached_registry.clone();
        let period = self
            .config
            .refresh_interval
            .unwrap_or(DEFAULT_RPC_CACHE_REFRESH_INTERVAL);
        let db = self.db.clone();

        // Spawn a background task to refresh the cache
        tokio::spawn(async move {
            info!(?period, "initializing rpc server cache refresh task");

            Self::refresh_registry(&db, &cached_registry).await;
            debug!("rpc server contracts cache initialized");

            // Periodic refresh in a separate loop outside the closure
            let mut refresh_interval = interval(period);
            loop {
                refresh_interval.tick().await;

                Self::refresh_registry(&db, &cached_registry).await;
                debug!("rpc state machine registry cache refreshed");
            }
        });
    }

    async fn refresh_registry(db: &Persister, cached_registry: &RwLock<SMRegistry>) {
        let config = {
            let registry_read_lock = cached_registry.read().await;
            registry_read_lock.cfg().clone()
        };

        info!("refreshing rpc server state machine registry cache from database");
        let sm_registry = db
            .recover_registry(config)
            .await
            .expect("must recover state machine registry from database");

        let mut cache_registry_lock = cached_registry.write().await;
        *cache_registry_lock = sm_registry;

        let deposit_count = cache_registry_lock.num_deposits();
        info!(%deposit_count, "rpc server state machine registry cache refresh complete");
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
            .operators
            .iter()
            .map(|operator| PublicKey::from(operator.signing_public_key()))
            .collect())
    }

    async fn get_operator_status(&self, operator_pk: PublicKey) -> RpcResult<RpcOperatorStatus> {
        let Ok(conversion) = convert_operator_pk_to_peer_id(&self.params, &operator_pk) else {
            // Avoid DoS attacks by just returning an error if the public key is invalid
            return Err(rpc_error(
                ErrorCode::InvalidRequest,
                "Invalid operator public key",
                operator_pk,
            ));
        };
        if self.command_handle.is_connected(&conversion, None).await {
            Ok(RpcOperatorStatus::Online)
        } else {
            Ok(RpcOperatorStatus::Offline)
        }
    }

    async fn get_deposit_indices(&self) -> RpcResult<Vec<DepositIdx>> {
        Ok(self.cached_registry.read().await.get_deposit_ids())
    }

    async fn get_deposit_info(&self, deposit_idx: DepositIdx) -> RpcResult<RpcDepositInfo> {
        let cached_registry = self.cached_registry.read().await;

        let Some(dsm) = cached_registry.get_deposit(&deposit_idx) else {
            return Err(rpc_error(
                ErrorCode::InvalidParams,
                "Deposit not found",
                deposit_idx,
            ));
        };

        let deposit_request_txid = dsm.context().deposit_request_outpoint().txid;
        let status = match dsm.state() {
            DepositState::Created { .. }
            | DepositState::GraphGenerated { .. }
            | DepositState::DepositNoncesCollected { .. }
            | DepositState::DepositPartialsCollected { .. } => RpcDepositStatus::InProgress,
            DepositState::Aborted => RpcDepositStatus::Failed {
                reason: "Deposit request spent elsewhere".to_string(),
            },
            _ => RpcDepositStatus::Complete {
                deposit_txid: dsm.context().deposit_outpoint().txid,
            },
        };

        Ok(RpcDepositInfo {
            status,
            deposit_idx,
            deposit_request_txid,
        })
    }

    async fn get_bridge_duties(&self) -> RpcResult<Vec<RpcBridgeDutyStatus>> {
        let cached_registry = self.cached_registry.read().await;

        Ok(cached_registry
            .deposits()
            .flat_map(|(&deposit_idx, dsm)| {
                bridge_duties_for_deposit(
                    deposit_idx,
                    dsm.state(),
                    dsm.context().deposit_request_outpoint().txid,
                )
            })
            .collect())
    }

    async fn get_bridge_duties_by_operator_pk(
        &self,
        operator_pk: PublicKey,
    ) -> RpcResult<Vec<RpcBridgeDutyStatus>> {
        let cached_registry = self.cached_registry.read().await;

        let Some(duties) = bridge_duties_for_operator_pk(&cached_registry, &operator_pk) else {
            return Err(rpc_error(
                ErrorCode::InvalidRequest,
                "Invalid operator public key",
                operator_pk,
            ));
        };

        Ok(duties)
    }

    async fn get_withdrawal_status(
        &self,
        deposit_idx: DepositIdx,
    ) -> RpcResult<Option<RpcWithdrawalStatus>> {
        let cached_registry = self.cached_registry.read().await;

        let Some(deposit_state) = cached_registry
            .get_deposit(&deposit_idx)
            .map(|dsm| dsm.state())
        else {
            return Ok(None);
        };

        Ok(withdrawal_status(deposit_state))
    }

    async fn get_reimbursement_status(
        &self,
        deposit_idx: DepositIdx,
    ) -> RpcResult<Option<RpcReimbursementStatus>> {
        let cached_registry = self.cached_registry.read().await;

        let Some(deposit_state) = cached_registry
            .get_deposit(&deposit_idx)
            .map(|dsm| dsm.state())
        else {
            return Ok(None);
        };

        let Some(assignee) = get_reimbursement_operator(deposit_state) else {
            return Err(rpc_error(
                ErrorCode::InvalidRequest,
                "Deposit has no assigned operator",
                deposit_idx,
            ));
        };

        let graph_idx = GraphIdx {
            deposit: deposit_idx,
            operator: assignee,
        };
        let Some(gsm) = cached_registry.get_graph(&graph_idx) else {
            return Err(rpc_error(
                ErrorCode::InternalError,
                "Missing graph for assigned deposit",
                format!("{graph_idx:?}"),
            ));
        };

        Ok(Some(reimbursement_status(gsm.state())))
    }

    async fn get_pending_withdrawals(&self) -> RpcResult<Vec<DepositIdx>> {
        Ok(self
            .cached_registry
            .read()
            .await
            .deposits()
            .filter_map(|(&deposit_idx, dsm)| {
                get_pending_assigned_operator(dsm.state()).map(|_assignee| deposit_idx)
            })
            .collect())
    }

    async fn get_pending_withdrawal_info(
        &self,
        deposit_idx: DepositIdx,
    ) -> RpcResult<Option<RpcPendingWithdrawalInfo>> {
        let cached_registry = self.cached_registry.read().await;

        let Some(deposit_state) = cached_registry
            .get_deposit(&deposit_idx)
            .map(|dsm| dsm.state())
        else {
            return Ok(None);
        };

        let Some(assignee) = get_pending_assigned_operator(deposit_state) else {
            return Ok(None);
        };

        let mut assigned_claim = None;
        let mut competing_claims = Vec::new();

        cached_registry
            .graphs()
            .filter(|(graph_idx, _gsm)| graph_idx.deposit == deposit_idx)
            .filter_map(|(graph_idx, gsm)| {
                active_claim_from_state(graph_idx.operator, gsm.state())
                    .map(|claim| (graph_idx.operator, claim))
            })
            .for_each(|(operator_idx, claim)| {
                if operator_idx == assignee {
                    assigned_claim = Some(claim);
                } else {
                    competing_claims.push(claim);
                }
            });

        let info = RpcPendingWithdrawalInfo {
            assigned_operator: assignee,
            assigned_claim,
            competing_claims,
        };

        Ok(Some(info))
    }

    async fn get_stake_status(&self) -> RpcResult<Vec<RpcOperatorStakeInfo>> {
        let cached_registry = self.cached_registry.read().await;
        Ok(cached_registry
            .stakes()
            .map(|(&operator_idx, sm)| RpcOperatorStakeInfo {
                operator_idx,
                state: stake_state_to_rpc(sm.state()),
            })
            .collect())
    }
}

#[async_trait]
impl StrataBridgeDaApiServer for BridgeRpc {
    async fn get_graph_data(&self, graph_idx: GraphIdx) -> RpcResult<Option<RpcGraphData>> {
        let cached_registry = self.cached_registry.read().await;
        let graph_cfg = cached_registry.cfg().graph.clone();

        Ok(cached_registry
            .get_graph(&graph_idx)
            .and_then(|gsm| graph_data_response(gsm.context(), gsm.state(), &graph_cfg)))
    }

    async fn get_aggregate_signatures(
        &self,
        graph_idx: GraphIdx,
    ) -> RpcResult<Option<RpcAggregateSignatures>> {
        let cached_registry = self.cached_registry.read().await;

        Ok(cached_registry
            .get_graph(&graph_idx)
            .and_then(|gsm| aggregate_signatures_response(graph_idx, gsm.state())))
    }

    async fn get_stake_data(&self, operator_idx: OperatorIdx) -> RpcResult<Option<RpcStakeData>> {
        let cached_registry = self.cached_registry.read().await;
        let stake_cfg = cached_registry.cfg().stake.clone();

        Ok(cached_registry
            .get_stake(&operator_idx)
            .and_then(|ssm| stake_data_response(ssm.context(), ssm.state(), &stake_cfg)))
    }

    async fn get_stake_aggregate_signatures(
        &self,
        operator_idx: OperatorIdx,
    ) -> RpcResult<Option<RpcStakeAggregateSignatures>> {
        let cached_registry = self.cached_registry.read().await;

        Ok(cached_registry
            .get_stake(&operator_idx)
            .and_then(|ssm| stake_aggregate_signatures_response(operator_idx, ssm.state())))
    }
}

/// Converts a *MuSig2* operator [`PublicKey`] to a *P2P* [`PeerId`].
///
/// Internally checks if the operator MuSig2 [`PublicKey`] is present in the configured operator
/// schedule, then fetches the corresponding P2P [`PublicKey`] from the same operator entry.
pub(crate) fn convert_operator_pk_to_peer_id(
    params: &Params,
    operator_pk: &PublicKey,
) -> anyhow::Result<PeerId> {
    params
        .keys
        .operators
        .iter()
        .find(|operator| operator.signing_key() == operator_pk.inner.x_only_public_key().0)
        .map(|operator| {
            LibP2pEdPublicKey::try_from_bytes(operator.p2p_key().as_ref())
                .map(|p2p_key| {
                    let pk: LibP2pPublicKey = p2p_key.into();
                    PeerId::from(pk)
                })
                .map_err(|err| anyhow::anyhow!("invalid p2p key in params: {err}"))
        })
        .transpose()?
        .ok_or_else(|| anyhow::anyhow!("operator public key not found in params"))
}

/// Returns an [`ErrorObjectOwned`] with the given code, message, and data.
/// Useful for creating custom error objects in RPC responses.
fn rpc_error<T: fmt::Display + Serialize>(
    err_code: ErrorCode,
    message: &str,
    data: T,
) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(err_code.code(), message, Some(data))
}
