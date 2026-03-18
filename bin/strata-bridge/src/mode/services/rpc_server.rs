use std::{fmt, sync::Arc};

use anyhow::Context;
use async_trait::async_trait;
use bitcoin::{PublicKey, Txid};
use chrono::{DateTime, Utc};
use jsonrpsee::{
    RpcModule,
    core::RpcResult,
    types::{ErrorCode, ErrorObjectOwned},
};
use libp2p::{PeerId, identity::PublicKey as LibP2pPublicKey};
use secp256k1::Parity;
use serde::Serialize;
use strata_bridge_db::fdb::client::FdbClient;
use strata_bridge_orchestrator::{
    persister::Persister,
    sm_registry::{SMConfig, SMRegistry},
};
use strata_bridge_rpc::{
    traits::{StrataBridgeControlApiServer, StrataBridgeMonitoringApiServer},
    types::{
        RpcBridgeDutyStatus, RpcClaimInfo, RpcDepositInfo, RpcDepositStatus, RpcOperatorStatus,
        RpcWithdrawalInfo,
    },
};
use strata_bridge_sm::deposit::state::DepositState;
use strata_p2p::swarm::handle::CommandHandle;
use strata_primitives::buf::Buf32;
use strata_tasks::TaskExecutor;
use tokio::{
    sync::{RwLock, oneshot},
    time::interval,
};
use tracing::{debug, info, warn};

use crate::{
    config::{Config, RpcConfig},
    constants::DEFAULT_RPC_CACHE_REFRESH_INTERVAL,
    mode::services::orchestrator::build_sm_config,
    params::Params,
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
    T: StrataBridgeControlApiServer + StrataBridgeMonitoringApiServer + Clone + Sync + Send,
{
    let mut rpc_module = RpcModule::new(rpc_impl.clone());
    let control_api = StrataBridgeControlApiServer::into_rpc(rpc_impl.clone());
    let monitoring_api = StrataBridgeMonitoringApiServer::into_rpc(rpc_impl.clone());
    rpc_module.merge(control_api).context("merge control api")?;
    rpc_module
        .merge(monitoring_api)
        .context("merge monitoring api")?;
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
            .covenant
            .iter()
            .map(|cov| {
                let secp_pk = cov.musig2.public_key(Parity::Even);
                PublicKey::from(secp_pk)
            })
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

    async fn get_deposit_requests(&self) -> RpcResult<Vec<Txid>> {
        let cached_registry = self.cached_registry.read().await;
        let deposit_requests = cached_registry
            .deposits()
            .map(|(_deposit_idx, dsm)| dsm.context().deposit_request_outpoint().txid)
            .collect();

        Ok(deposit_requests)
    }

    async fn get_deposit_request_info(
        &self,
        deposit_request_txid: Txid,
    ) -> RpcResult<RpcDepositInfo> {
        let cached_registry = self.cached_registry.read().await;

        let Some(info) = cached_registry
            .deposits()
            .into_iter()
            .find(|(_deposit_idx, dsm)| {
                dsm.context().deposit_request_outpoint().txid == deposit_request_txid
            })
            .map(|(_deposit_idx, dsm)| match dsm.state() {
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
            })
            .map(|status| RpcDepositInfo {
                status,
                deposit_request_txid,
            })
        else {
            return Err(rpc_error(
                ErrorCode::InvalidParams,
                "Deposit request not found",
                deposit_request_txid,
            ));
        };

        Ok(info)
    }

    async fn get_bridge_duties(&self) -> RpcResult<Vec<RpcBridgeDutyStatus>> {
        // TODO: <https://atlassian.alpenlabs.net/browse/STR-2657>
        // Update this based on monitoring requirements.
        Ok(vec![])
    }

    async fn get_bridge_duties_by_operator_pk(
        &self,
        _operator_pk: PublicKey,
    ) -> RpcResult<Vec<RpcBridgeDutyStatus>> {
        // TODO: <https://atlassian.alpenlabs.net/browse/STR-2657>
        // Update this based on monitoring requirements.
        Ok(vec![])
    }

    async fn get_withdrawals(&self) -> RpcResult<Vec<Buf32>> {
        // TODO: <https://atlassian.alpenlabs.net/browse/STR-2657>
        // Update this based on monitoring requirements.
        Ok(vec![])
    }

    async fn get_withdrawal_info(
        &self,
        _withdrawal_request_txid: Buf32,
    ) -> RpcResult<Option<RpcWithdrawalInfo>> {
        // TODO: <https://atlassian.alpenlabs.net/browse/STR-2657>
        // Update this based on monitoring requirements.
        Ok(None)
    }

    async fn get_claims(&self) -> RpcResult<Vec<Txid>> {
        // TODO: <https://atlassian.alpenlabs.net/browse/STR-2657>
        // Update this based on monitoring requirements.
        Ok(vec![])
    }

    async fn get_claim_info(&self, _claim_txid: Txid) -> RpcResult<Option<RpcClaimInfo>> {
        // TODO: <https://atlassian.alpenlabs.net/browse/STR-2657>
        // Update this based on monitoring requirements.
        Ok(None)
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
    params
        .keys
        .covenant
        .iter()
        .find(|cov| cov.musig2 == operator_pk.inner.x_only_public_key().0)
        .map(|cov| {
            let pk: LibP2pPublicKey = cov.p2p.clone().into();
            PeerId::from(pk)
        })
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
