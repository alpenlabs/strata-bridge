//! Bootstraps an RPC server for the operator.

use anyhow::Context;
use async_trait::async_trait;
use bitcoin::{OutPoint, PublicKey, Txid};
use chrono::{DateTime, Utc};
use jsonrpsee::{core::RpcResult, RpcModule};
use strata_bridge_db::persistent::sqlite::SqliteDb;
use strata_bridge_primitives::{
    duties::BridgeDuty,
    types::{OperatorIdx, PublickeyTable},
};
use strata_bridge_rpc::{
    traits::{StrataBridgeControlApiServer, StrataBridgeMonitoringApiServer},
    types::{RpcClaimInfo, RpcDepositInfo, RpcOperatorStatus, RpcWithdrawalInfo},
};
use tokio::sync::oneshot;
use tracing::{info, warn};

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

/// Struct to implement the [`StrataBridgeControlApiServer`] on. Contains
/// fields corresponding the global context for the RPC.
#[derive(Clone)]
pub(crate) struct BridgeRpc {
    /// Node start time.
    start_time: DateTime<Utc>,

    /// Database handle.
    db: SqliteDb,
}

impl BridgeRpc {
    /// Create a new instance of [`BridgeRpc`].
    pub(crate) fn new(db: SqliteDb) -> Self {
        Self {
            start_time: Utc::now(),
            db,
        }
    }
}

#[async_trait]
impl StrataBridgeControlApiServer for BridgeRpc {
    async fn get_uptime(&self) -> RpcResult<u64> {
        let current_time = Utc::now().timestamp();
        let start_time = self.start_time.timestamp();

        // The user might care about their system time being incorrect.
        if current_time <= start_time {
            return Err(jsonrpsee::types::ErrorObjectOwned::owned::<_>(
                -32000,
                "system time may be inaccurate", // `start_time` may have been incorrect too
                Some(current_time.saturating_sub(start_time)),
            ));
        }

        Ok(current_time.abs_diff(start_time))
    }
}

#[async_trait]
impl StrataBridgeMonitoringApiServer for BridgeRpc {
    async fn get_bridge_operators(&self) -> RpcResult<PublickeyTable> {
        unimplemented!()
    }

    async fn get_operator_status(&self, operator_idx: OperatorIdx) -> RpcResult<RpcOperatorStatus> {
        unimplemented!()
    }

    async fn get_deposit_info(
        &self,
        deposit_request_outpoint: OutPoint,
    ) -> RpcResult<RpcDepositInfo> {
        unimplemented!()
    }

    async fn get_bridge_duties(&self) -> RpcResult<Vec<BridgeDuty>> {
        unimplemented!()
    }

    async fn get_bridge_duties_by_operator_pk(
        &self,
        operator_pk: PublicKey,
    ) -> RpcResult<Vec<BridgeDuty>> {
        unimplemented!()
    }

    async fn get_bridge_duties_by_operator_id(
        &self,
        operator_id: OperatorIdx,
    ) -> RpcResult<Vec<BridgeDuty>> {
        unimplemented!()
    }

    async fn get_withdrawal_info(
        &self,
        withdrawal_outpoint: OutPoint,
    ) -> RpcResult<RpcWithdrawalInfo> {
        unimplemented!()
    }

    async fn get_claims(&self) -> RpcResult<Vec<Txid>> {
        unimplemented!()
    }

    async fn get_claim_info(&self, claim_txid: Txid) -> RpcResult<RpcClaimInfo> {
        unimplemented!()
    }
}
