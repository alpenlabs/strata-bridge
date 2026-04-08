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
use secp256k1::{Parity, schnorr};
use serde::Serialize;
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
        RpcActiveClaim, RpcAggregateSignatures, RpcBridgeDutyStatus, RpcClaimInfo, RpcClaimPhase,
        RpcDepositInfo, RpcDepositStatus, RpcGraphData, RpcOperatorStatus,
        RpcPendingWithdrawalInfo, RpcWithdrawalInfo,
    },
};
use strata_bridge_sm::{
    deposit::state::DepositState,
    graph::{config::GraphSMCfg, context::GraphSMCtx, state::GraphState},
};
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

    async fn get_pending_withdrawals(&self) -> RpcResult<Vec<DepositIdx>> {
        Ok(self
            .cached_registry
            .read()
            .await
            .deposits()
            .filter_map(|(&deposit_idx, dsm)| {
                get_assigned_operator(dsm.state()).map(|_assignee| deposit_idx)
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

        let Some(assignee) = get_assigned_operator(deposit_state) else {
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
}

const fn get_assigned_operator(state: &DepositState) -> Option<OperatorIdx> {
    match state {
        DepositState::Assigned { assignee, .. }
        | DepositState::Fulfilled { assignee, .. }
        | DepositState::PayoutDescriptorReceived { assignee, .. }
        | DepositState::PayoutNoncesCollected { assignee, .. }
        | DepositState::CooperativePathFailed { assignee, .. } => Some(*assignee),
        _ => None,
    }
}

const fn active_claim_from_state(
    operator: OperatorIdx,
    state: &GraphState,
) -> Option<RpcActiveClaim> {
    let (claim_txid, fulfillment_txid, phase) = match state {
        GraphState::Claimed {
            graph_summary,
            fulfillment_txid,
            ..
        } => (
            graph_summary.claim,
            fulfillment_txid,
            RpcClaimPhase::Claimed,
        ),
        GraphState::Contested {
            graph_summary,
            fulfillment_txid,
            ..
        } => (
            graph_summary.claim,
            fulfillment_txid,
            RpcClaimPhase::Contested,
        ),
        GraphState::BridgeProofPosted {
            graph_summary,
            fulfillment_txid,
            ..
        } => (
            graph_summary.claim,
            fulfillment_txid,
            RpcClaimPhase::BridgeProofPosted,
        ),
        GraphState::BridgeProofTimedout {
            claim_txid,
            fulfillment_txid,
            ..
        } => (
            *claim_txid,
            fulfillment_txid,
            RpcClaimPhase::BridgeProofTimedout,
        ),
        GraphState::CounterProofPosted {
            graph_summary,
            fulfillment_txid,
            ..
        } => (
            graph_summary.claim,
            fulfillment_txid,
            RpcClaimPhase::CounterProofPosted,
        ),
        GraphState::AllNackd {
            claim_txid,
            fulfillment_txid,
            ..
        } => (*claim_txid, fulfillment_txid, RpcClaimPhase::AllNackd),
        GraphState::Acked {
            claim_txid,
            fulfillment_txid,
            ..
        } => (*claim_txid, fulfillment_txid, RpcClaimPhase::Acked),
        _ => return None,
    };

    Some(RpcActiveClaim {
        operator,
        claim_txid,
        fulfilled: fulfillment_txid.is_some(),
        phase,
    })
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
}

fn graph_data_response(
    context: &GraphSMCtx,
    state: &GraphState,
    graph_cfg: &GraphSMCfg,
) -> Option<RpcGraphData> {
    let graph_data = graph_data_from_state(state)?;
    let setup = context.generate_setup_params(graph_cfg);

    Some(RpcGraphData {
        context: context.clone(),
        setup,
        deposit: *graph_data,
    })
}

fn aggregate_signatures_response(
    graph_idx: GraphIdx,
    state: &GraphState,
) -> Option<RpcAggregateSignatures> {
    let signatures = aggregate_signatures_from_state(state)?;

    Some(RpcAggregateSignatures {
        graph_idx,
        signatures: signatures.to_vec(),
    })
}

const fn graph_data_from_state(
    state: &GraphState,
) -> Option<&strata_bridge_tx_graph::game_graph::DepositParams> {
    match state {
        GraphState::GraphGenerated { graph_data, .. }
        | GraphState::AdaptorsVerified { graph_data, .. }
        | GraphState::NoncesCollected { graph_data, .. }
        | GraphState::GraphSigned { graph_data, .. }
        | GraphState::Assigned { graph_data, .. }
        | GraphState::Fulfilled { graph_data, .. }
        | GraphState::Claimed { graph_data, .. }
        | GraphState::Contested { graph_data, .. }
        | GraphState::BridgeProofPosted { graph_data, .. }
        | GraphState::BridgeProofTimedout { graph_data, .. }
        | GraphState::CounterProofPosted { graph_data, .. } => Some(graph_data),
        _ => None,
    }
}

fn aggregate_signatures_from_state(state: &GraphState) -> Option<&[schnorr::Signature]> {
    match state {
        GraphState::GraphSigned { signatures, .. }
        | GraphState::Assigned { signatures, .. }
        | GraphState::Fulfilled { signatures, .. }
        | GraphState::Claimed { signatures, .. }
        | GraphState::Contested { signatures, .. }
        | GraphState::BridgeProofPosted { signatures, .. }
        | GraphState::BridgeProofTimedout { signatures, .. }
        | GraphState::CounterProofPosted { signatures, .. } => Some(signatures),
        _ => None,
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, num::NonZero};

    use bitcoin::{
        Amount, Network, OutPoint,
        hashes::{Hash, sha256},
        relative,
    };
    use secp256k1::schnorr::Signature;
    use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx};
    use strata_bridge_rpc::types::RpcClaimPhase;
    use strata_bridge_sm::graph::{config::GraphSMCfg, context::GraphSMCtx, state::GraphState};
    use strata_bridge_test_utils::{
        bitcoin::generate_xonly_pubkey,
        bridge_fixtures::{
            TEST_DEPOSIT_AMOUNT, TEST_MAGIC_BYTES, TEST_OPERATOR_FEE, TEST_POV_IDX,
            random_p2tr_desc, test_operator_table,
        },
        prelude::generate_txid,
    };
    use strata_bridge_tx_graph::game_graph::{DepositParams, GameGraphSummary, ProtocolParams};
    use strata_predicate::PredicateKey;

    use super::{active_claim_from_state, aggregate_signatures_response, graph_data_response};

    const DEPOSIT_IDX: DepositIdx = 3;
    const OPERATOR_IDX: OperatorIdx = 1;

    fn test_graph_idx() -> GraphIdx {
        GraphIdx {
            deposit: DEPOSIT_IDX,
            operator: OPERATOR_IDX,
        }
    }

    fn test_graph_data() -> DepositParams {
        DepositParams {
            game_index: NonZero::new(DEPOSIT_IDX + 1).expect("non-zero"),
            claim_funds: OutPoint::new(bitcoin::Txid::all_zeros(), 1),
            deposit_outpoint: OutPoint::new(bitcoin::Txid::all_zeros(), 1),
        }
    }

    fn test_graph_ctx() -> GraphSMCtx {
        GraphSMCtx {
            graph_idx: test_graph_idx(),
            deposit_outpoint: OutPoint::new(bitcoin::Txid::all_zeros(), 7),
            stake_outpoint: OutPoint::new(bitcoin::Txid::all_zeros(), 8),
            unstaking_image: sha256::Hash::hash(b"test"),
            operator_table: test_operator_table(3, TEST_POV_IDX),
        }
    }

    fn test_graph_cfg() -> GraphSMCfg {
        GraphSMCfg {
            game_graph_params: ProtocolParams {
                network: Network::Regtest,
                magic_bytes: TEST_MAGIC_BYTES.into(),
                contest_timelock: relative::Height::from_height(10),
                proof_timelock: relative::Height::from_height(5),
                ack_timelock: relative::Height::from_height(5),
                nack_timelock: relative::Height::from_height(5),
                contested_payout_timelock: relative::Height::from_height(10),
                counterproof_n_bytes: NonZero::new(128).expect("non-zero"),
                deposit_amount: TEST_DEPOSIT_AMOUNT,
                stake_amount: Amount::from_sat(20_000),
            },
            operator_fee: TEST_OPERATOR_FEE,
            operator_adaptor_keys: (0..3).map(|_| generate_xonly_pubkey()).collect(),
            admin_pubkey: generate_xonly_pubkey(),
            watchtower_fault_pubkeys: (0..2).map(|_| generate_xonly_pubkey()).collect(),
            payout_descs: (0..3).map(|_| random_p2tr_desc()).collect(),
            bridge_proof_predicate: PredicateKey::always_accept(),
        }
    }

    fn test_graph_summary() -> GameGraphSummary {
        GameGraphSummary {
            claim: generate_txid(),
            contest: generate_txid(),
            bridge_proof_timeout: generate_txid(),
            counterproofs: vec![],
            slash: generate_txid(),
            uncontested_payout: generate_txid(),
            contested_payout: generate_txid(),
        }
    }

    #[test]
    fn graph_data_response_returns_graph_data_for_matching_claim() {
        let graph_ctx = test_graph_ctx();
        let graph_cfg = test_graph_cfg();
        let graph_data = test_graph_data();
        let graph_summary = test_graph_summary();
        let state = GraphState::GraphGenerated {
            last_block_height: 100,
            graph_data,
            graph_summary: graph_summary.clone(),
        };

        let response = graph_data_response(&graph_ctx, &state, &graph_cfg)
            .expect("graph data should be returned");

        assert_eq!(response.context, graph_ctx);
        assert_eq!(response.setup, graph_ctx.generate_setup_params(&graph_cfg));
        assert_eq!(response.deposit, graph_data);
    }

    #[test]
    fn graph_data_response_returns_none_before_graph_is_generated() {
        let state = GraphState::Created {
            last_block_height: 100,
        };

        let response = graph_data_response(&test_graph_ctx(), &state, &test_graph_cfg());

        assert!(response.is_none());
    }

    #[test]
    fn aggregate_signatures_response_returns_hex_signatures_for_matching_claim() {
        let graph_idx = test_graph_idx();
        let graph_summary = test_graph_summary();
        let signatures = vec![
            Signature::from_slice(&[0x0a; 64]).expect("valid signature"),
            Signature::from_slice(&[0x0b; 64]).expect("valid signature"),
        ];
        let expected_signatures = signatures.clone();
        let state = GraphState::GraphSigned {
            last_block_height: 100,
            graph_data: test_graph_data(),
            graph_summary: graph_summary.clone(),
            agg_nonces: Some(vec![]),
            signatures,
        };

        let response = aggregate_signatures_response(graph_idx, &state)
            .expect("signatures should be returned");

        assert_eq!(response.graph_idx, graph_idx);
        assert_eq!(response.signatures, expected_signatures);
    }

    #[test]
    fn aggregate_signatures_response_returns_none_before_graph_is_signed() {
        let state = GraphState::NoncesCollected {
            last_block_height: 100,
            graph_data: test_graph_data(),
            graph_summary: test_graph_summary(),
            pubnonces: BTreeMap::new(),
            agg_nonces: vec![],
            partial_signatures: BTreeMap::new(),
        };

        let response = aggregate_signatures_response(test_graph_idx(), &state);

        assert!(response.is_none());
    }

    #[test]
    fn active_claim_from_state_returns_fulfilled_claim_in_claimed_state() {
        let graph_summary = test_graph_summary();
        let state = GraphState::Claimed {
            last_block_height: 100,
            graph_data: test_graph_data(),
            graph_summary: graph_summary.clone(),
            signatures: vec![],
            fulfillment_txid: Some(generate_txid()),
            fulfillment_block_height: Some(90),
            claim_block_height: 100,
        };

        let claim =
            active_claim_from_state(OPERATOR_IDX, &state).expect("claim should be returned");

        assert_eq!(claim.operator, OPERATOR_IDX);
        assert_eq!(claim.claim_txid, graph_summary.claim);
        assert!(claim.fulfilled);
        assert_eq!(claim.phase, RpcClaimPhase::Claimed);
    }

    #[test]
    fn active_claim_from_state_returns_unfulfilled_claim_in_claimed_state() {
        let graph_summary = test_graph_summary();
        let state = GraphState::Claimed {
            last_block_height: 100,
            graph_data: test_graph_data(),
            graph_summary: graph_summary.clone(),
            signatures: vec![],
            fulfillment_txid: None,
            fulfillment_block_height: None,
            claim_block_height: 100,
        };

        let claim =
            active_claim_from_state(OPERATOR_IDX, &state).expect("claim should be returned");

        assert!(!claim.fulfilled);
        assert_eq!(claim.phase, RpcClaimPhase::Claimed);
    }

    #[test]
    fn active_claim_from_state_returns_none_before_claim() {
        let state = GraphState::Fulfilled {
            last_block_height: 100,
            graph_data: test_graph_data(),
            graph_summary: test_graph_summary(),
            coop_payout_failed: false,
            assignee: OPERATOR_IDX,
            signatures: vec![],
            fulfillment_txid: generate_txid(),
            fulfillment_block_height: 90,
        };

        let claim = active_claim_from_state(OPERATOR_IDX, &state);

        assert!(claim.is_none());
    }

    #[test]
    fn active_claim_from_state_returns_contested_phase() {
        let graph_summary = test_graph_summary();
        let state = GraphState::Contested {
            last_block_height: 100,
            graph_data: test_graph_data(),
            graph_summary: graph_summary.clone(),
            signatures: vec![],
            fulfillment_txid: Some(generate_txid()),
            fulfillment_block_height: Some(90),
            contest_block_height: 100,
        };

        let claim =
            active_claim_from_state(OPERATOR_IDX, &state).expect("claim should be returned");

        assert!(claim.fulfilled);
        assert_eq!(claim.phase, RpcClaimPhase::Contested);
    }
}
