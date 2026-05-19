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
        RpcActiveClaim, RpcAggregateSignatures, RpcBridgeDutyStatus, RpcClaimPhase, RpcDepositInfo,
        RpcDepositStatus, RpcGraphData, RpcOperatorStakeInfo, RpcOperatorStatus,
        RpcPendingWithdrawalInfo, RpcReimbursementStatus, RpcStakeState, RpcWithdrawalStatus,
    },
};
use strata_bridge_sm::{
    deposit::state::DepositState,
    graph::{config::GraphSMCfg, context::GraphSMCtx, state::GraphState},
    stake::state::StakeState,
};
use strata_p2p::swarm::handle::CommandHandle;
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

        let Some(operator_idx) = operator_idx_from_registry(&cached_registry, &operator_pk) else {
            return Err(rpc_error(
                ErrorCode::InvalidRequest,
                "Invalid operator public key",
                operator_pk,
            ));
        };

        Ok(cached_registry
            .deposits()
            .flat_map(|(&deposit_idx, dsm)| {
                bridge_duties_for_deposit(
                    deposit_idx,
                    dsm.state(),
                    dsm.context().deposit_request_outpoint().txid,
                )
            })
            .filter(|duty| duty_applies_to_operator(duty, operator_idx))
            .collect())
    }

    async fn get_withdrawal_status(
        &self,
        _deposit_idx: DepositIdx,
    ) -> RpcResult<Option<RpcWithdrawalStatus>> {
        // TODO: <https://alpenlabs.atlassian.net/browse/STR-2657>
        // Update this based on monitoring requirements.
        Ok(None)
    }

    async fn get_reimbursement_status(
        &self,
        _deposit_idx: DepositIdx,
    ) -> RpcResult<Option<RpcReimbursementStatus>> {
        // TODO: <https://alpenlabs.atlassian.net/browse/STR-2657>
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

const fn stake_state_to_rpc(state: &StakeState) -> RpcStakeState {
    match state {
        StakeState::Created { .. } => RpcStakeState::Created,
        StakeState::StakeGraphGenerated { .. } => RpcStakeState::StakeGraphGenerated,
        StakeState::UnstakingNoncesCollected { .. } => RpcStakeState::UnstakingNoncesCollected,
        StakeState::UnstakingSigned { .. } => RpcStakeState::UnstakingSigned,
        StakeState::Confirmed { summary, .. } => RpcStakeState::Confirmed {
            stake_txid: summary.stake,
        },
        StakeState::PreimageRevealed { .. } => RpcStakeState::PreimageRevealed,
        StakeState::Unstaked { unstaking_txid, .. } => RpcStakeState::Unstaked {
            unstaking_txid: *unstaking_txid,
        },
        StakeState::Slashed { slash_txid, .. } => RpcStakeState::Slashed {
            slash_txid: *slash_txid,
        },
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

/// Builds the deposit and withdrawal duties currently implied by a single deposit state machine.
fn bridge_duties_for_deposit(
    deposit_idx: DepositIdx,
    state: &DepositState,
    deposit_request_txid: Txid,
) -> Vec<RpcBridgeDutyStatus> {
    let mut duties = Vec::new();

    if has_deposit_duty(state) {
        duties.push(RpcBridgeDutyStatus::Deposit {
            deposit_idx,
            deposit_request_txid,
        });
    }

    if let DepositState::Assigned { assignee, .. } = state {
        duties.push(RpcBridgeDutyStatus::Withdrawal {
            deposit_idx,
            assigned_operator_idx: *assignee,
        });
    }

    duties
}

/// Returns whether the deposit state still requires operators to publish the deposit transaction.
const fn has_deposit_duty(state: &DepositState) -> bool {
    matches!(
        state,
        DepositState::Created { .. }
            | DepositState::GraphGenerated { .. }
            | DepositState::DepositNoncesCollected { .. }
            | DepositState::DepositPartialsCollected { .. }
    )
}

/// Returns whether a bridge duty applies to a resolved operator index.
const fn duty_applies_to_operator(duty: &RpcBridgeDutyStatus, operator_idx: OperatorIdx) -> bool {
    match duty {
        RpcBridgeDutyStatus::Deposit { .. } => true,
        RpcBridgeDutyStatus::Withdrawal {
            assigned_operator_idx,
            ..
        } => *assigned_operator_idx == operator_idx,
    }
}

/// Resolves a MuSig2 public key to an operator index using recovered deposit state-machine tables.
fn operator_idx_from_registry(
    registry: &SMRegistry,
    operator_pk: &PublicKey,
) -> Option<OperatorIdx> {
    registry.deposits().find_map(|(_deposit_idx, sm)| {
        sm.context()
            .operator_table()
            .btc_key_to_idx(&operator_pk.inner)
    })
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
    let setup = context.generate_setup_params(graph_cfg, graph_data);

    Some(RpcGraphData {
        context: context.clone(),
        setup,
        deposit: graph_data.clone(),
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
    use std::{collections::BTreeMap, num::NonZero, sync::Arc};

    use bitcoin::{
        Amount, Network, OutPoint, PublicKey, Txid,
        hashes::{Hash, sha256},
        relative,
    };
    use secp256k1::schnorr::Signature;
    use strata_bridge_connectors::prelude::{DepositRequestConnector, NOfNConnector};
    use strata_bridge_orchestrator::sm_registry::{SMConfig, SMRegistry};
    use strata_bridge_primitives::{
        operator_table::OperatorTable,
        types::{DepositIdx, GraphIdx, OperatorIdx},
    };
    use strata_bridge_rpc::types::{RpcBridgeDutyStatus, RpcClaimPhase};
    use strata_bridge_sm::{
        deposit::{
            config::DepositSMCfg, context::DepositSMCtx, machine::DepositSM, state::DepositState,
        },
        graph::{config::GraphSMCfg, context::GraphSMCtx, state::GraphState},
        stake::config::StakeSMCfg,
    };
    use strata_bridge_test_utils::{
        bitcoin::{generate_tx, generate_xonly_pubkey},
        bridge_fixtures::{
            TEST_DEPOSIT_AMOUNT, TEST_MAGIC_BYTES, TEST_OPERATOR_FEE, TEST_POV_IDX,
            TEST_RECOVERY_DELAY, random_p2tr_desc, test_operator_table,
        },
        musig2::{generate_agg_nonce, generate_partial_signature, generate_pubnonce},
        prelude::generate_txid,
    };
    use strata_bridge_tx_graph::{
        game_graph::{DepositParams, GameGraphSummary, ProtocolParams},
        stake_graph::ProtocolParams as StakeProtocolParams,
        transactions::{
            cooperative_payout::{CooperativePayoutData, CooperativePayoutTx},
            deposit::{DepositData, DepositTx},
        },
    };
    use strata_predicate::PredicateKey;

    use super::{
        active_claim_from_state, aggregate_signatures_response, bridge_duties_for_deposit,
        duty_applies_to_operator, graph_data_response, operator_idx_from_registry,
    };

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
            adaptor_pubkeys: (0..2).map(|_| generate_xonly_pubkey()).collect(),
            fault_pubkeys: (0..2).map(|_| generate_xonly_pubkey()).collect(),
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
                counterproof_n_data: NonZero::new(128).expect("non-zero"),
                deposit_amount: TEST_DEPOSIT_AMOUNT,
                stake_amount: Amount::from_sat(20_000),
            },
            operator_fee: TEST_OPERATOR_FEE,
            admin_pubkey: generate_xonly_pubkey(),
            payout_descs: (0..3).map(|_| random_p2tr_desc()).collect(),
            bridge_proof_predicate: PredicateKey::always_accept(),
        }
    }

    fn test_deposit_tx() -> DepositTx {
        let n_of_n_pubkey = generate_xonly_pubkey();
        let deposit_connector =
            NOfNConnector::new(Network::Regtest, n_of_n_pubkey, TEST_DEPOSIT_AMOUNT);
        let deposit_request_connector = DepositRequestConnector::new(
            Network::Regtest,
            n_of_n_pubkey,
            generate_xonly_pubkey(),
            relative::Height::from_height(144),
            DepositTx::drt_required(TEST_DEPOSIT_AMOUNT),
        );

        DepositTx::new(
            DepositData {
                deposit_idx: DEPOSIT_IDX,
                deposit_request_outpoint: OutPoint::new(Txid::all_zeros(), 0),
                magic_bytes: TEST_MAGIC_BYTES.into(),
            },
            deposit_connector,
            deposit_request_connector,
        )
    }

    fn test_cooperative_payout_tx() -> CooperativePayoutTx {
        let deposit_connector = NOfNConnector::new(
            Network::Regtest,
            generate_xonly_pubkey(),
            TEST_DEPOSIT_AMOUNT,
        );

        CooperativePayoutTx::new(
            CooperativePayoutData {
                deposit_outpoint: OutPoint::new(Txid::all_zeros(), 1),
            },
            deposit_connector,
            random_p2tr_desc(),
        )
    }

    fn test_sm_config() -> SMConfig {
        SMConfig {
            deposit: Arc::new(DepositSMCfg {
                network: Network::Regtest,
                cooperative_payout_timeout_blocks: 144,
                deposit_amount: TEST_DEPOSIT_AMOUNT,
                operator_fee: TEST_OPERATOR_FEE,
                magic_bytes: TEST_MAGIC_BYTES.into(),
                recovery_delay: TEST_RECOVERY_DELAY,
            }),
            graph: Arc::new(test_graph_cfg()),
            stake: Arc::new(StakeSMCfg {
                protocol_params: StakeProtocolParams {
                    network: Network::Regtest,
                    magic_bytes: TEST_MAGIC_BYTES.into(),
                    unstaking_timelock: relative::Height::from_height(144),
                    stake_amount: Amount::from_sat(20_000),
                },
            }),
        }
    }

    fn test_deposit_sm(deposit_idx: DepositIdx, operator_table: OperatorTable) -> DepositSM {
        DepositSM {
            context: DepositSMCtx {
                deposit_idx,
                deposit_request_outpoint: OutPoint::new(Txid::all_zeros(), 1),
                deposit_outpoint: OutPoint::new(Txid::all_zeros(), 2),
                operator_table,
            },
            state: DepositState::Deposited {
                last_block_height: 100,
            },
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
            graph_data: graph_data.clone(),
            graph_summary: graph_summary.clone(),
        };

        let response = graph_data_response(&graph_ctx, &state, &graph_cfg)
            .expect("graph data should be returned");

        assert_eq!(response.context, graph_ctx);
        assert_eq!(
            response.setup,
            graph_ctx.generate_setup_params(&graph_cfg, &graph_data)
        );
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

    #[test]
    fn bridge_duties_for_deposit_reports_each_deposit_state() {
        let deposit_request_txid = generate_txid();
        let claim_txids = BTreeMap::from([(OPERATOR_IDX, generate_txid())]);
        let pubnonces = BTreeMap::from([(OPERATOR_IDX, generate_pubnonce())]);
        let partial_signatures = BTreeMap::from([(OPERATOR_IDX, generate_partial_signature())]);
        let deposit_duty = vec![RpcBridgeDutyStatus::Deposit {
            deposit_idx: DEPOSIT_IDX,
            deposit_request_txid,
        }];
        let withdrawal_duty = vec![RpcBridgeDutyStatus::Withdrawal {
            deposit_idx: DEPOSIT_IDX,
            assigned_operator_idx: OPERATOR_IDX,
        }];
        let no_duties = Vec::<RpcBridgeDutyStatus>::new();

        let cases = vec![
            (
                "Created",
                DepositState::Created {
                    deposit_transaction: test_deposit_tx(),
                    last_block_height: 100,
                    claim_txids: claim_txids.clone(),
                },
                deposit_duty.clone(),
            ),
            (
                "GraphGenerated",
                DepositState::GraphGenerated {
                    deposit_transaction: test_deposit_tx(),
                    last_block_height: 100,
                    claim_txids: claim_txids.clone(),
                    pubnonces: pubnonces.clone(),
                },
                deposit_duty.clone(),
            ),
            (
                "DepositNoncesCollected",
                DepositState::DepositNoncesCollected {
                    deposit_transaction: test_deposit_tx(),
                    last_block_height: 100,
                    claim_txids,
                    agg_nonce: generate_agg_nonce(),
                    pubnonces: pubnonces.clone(),
                    partial_signatures: partial_signatures.clone(),
                },
                deposit_duty.clone(),
            ),
            (
                "DepositPartialsCollected",
                DepositState::DepositPartialsCollected {
                    last_block_height: 100,
                    deposit_transaction: generate_tx(1, 1),
                },
                deposit_duty,
            ),
            (
                "Deposited",
                DepositState::Deposited {
                    last_block_height: 100,
                },
                no_duties.clone(),
            ),
            (
                "Assigned",
                DepositState::Assigned {
                    last_block_height: 100,
                    assignee: OPERATOR_IDX,
                    deadline: 120,
                    recipient_desc: random_p2tr_desc(),
                },
                withdrawal_duty,
            ),
            (
                "Fulfilled",
                DepositState::Fulfilled {
                    last_block_height: 100,
                    assignee: OPERATOR_IDX,
                    fulfillment_txid: generate_txid(),
                    fulfillment_height: 95,
                    cooperative_payout_deadline: 120,
                },
                no_duties.clone(),
            ),
            (
                "PayoutDescriptorReceived",
                DepositState::PayoutDescriptorReceived {
                    last_block_height: 100,
                    assignee: OPERATOR_IDX,
                    cooperative_payment_deadline: 120,
                    cooperative_payout_tx: test_cooperative_payout_tx(),
                    payout_nonces: pubnonces.clone(),
                },
                no_duties.clone(),
            ),
            (
                "PayoutNoncesCollected",
                DepositState::PayoutNoncesCollected {
                    last_block_height: 100,
                    assignee: OPERATOR_IDX,
                    cooperative_payout_tx: test_cooperative_payout_tx(),
                    cooperative_payment_deadline: 120,
                    payout_nonces: pubnonces,
                    payout_aggregated_nonce: generate_agg_nonce(),
                    payout_partial_signatures: partial_signatures,
                },
                no_duties.clone(),
            ),
            (
                "CooperativePathFailed",
                DepositState::CooperativePathFailed {
                    assignee: OPERATOR_IDX,
                    last_block_height: 100,
                },
                no_duties.clone(),
            ),
            ("Spent", DepositState::Spent, no_duties.clone()),
            ("Aborted", DepositState::Aborted, no_duties),
        ];

        for (state_name, state, expected_duties) in cases {
            assert_eq!(
                bridge_duties_for_deposit(DEPOSIT_IDX, &state, deposit_request_txid),
                expected_duties,
                "unexpected duties for {state_name}",
            );
        }
    }

    #[test]
    fn operator_idx_from_registry_checks_until_btc_key_is_found() {
        let mut registry = SMRegistry::new(test_sm_config());
        let table_without_operator = test_operator_table(1, TEST_POV_IDX);
        let table_with_operator = test_operator_table(3, TEST_POV_IDX);
        let operator_pk = PublicKey::from(
            table_with_operator
                .idx_to_btc_key(&OPERATOR_IDX)
                .expect("operator should be in test operator table"),
        );

        registry
            .insert_deposit(0, test_deposit_sm(0, table_without_operator))
            .expect("first test deposit should be inserted");
        registry
            .insert_deposit(1, test_deposit_sm(1, table_with_operator))
            .expect("second test deposit should be inserted");

        let operator_idx = operator_idx_from_registry(&registry, &operator_pk);

        assert_eq!(operator_idx, Some(OPERATOR_IDX));
    }

    #[test]
    fn duty_applies_to_operator_matches_withdrawal_assignee() {
        let deposit_duty = RpcBridgeDutyStatus::Deposit {
            deposit_idx: DEPOSIT_IDX,
            deposit_request_txid: generate_txid(),
        };
        let withdrawal_duty = RpcBridgeDutyStatus::Withdrawal {
            deposit_idx: DEPOSIT_IDX,
            assigned_operator_idx: OPERATOR_IDX,
        };

        assert!(duty_applies_to_operator(&deposit_duty, OPERATOR_IDX));
        assert!(duty_applies_to_operator(&withdrawal_duty, OPERATOR_IDX));
        assert!(!duty_applies_to_operator(
            &withdrawal_duty,
            OPERATOR_IDX + 1
        ));
    }
}
