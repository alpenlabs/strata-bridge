//! Bootstraps an RPC server for the operator.

use anyhow::Context;
use async_trait::async_trait;
use bitcoin::{OutPoint, PublicKey, Txid};
use chrono::{DateTime, Utc};
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned, RpcModule};
use secp256k1::Parity;
use strata_bridge_db::{persistent::sqlite::SqliteDb, tracker::DutyTrackerDb};
use strata_bridge_primitives::duties::{
    BridgeDuty, ClaimStatus, DepositRequestStatus, WithdrawalStatus,
};
use strata_bridge_rpc::{
    traits::{StrataBridgeControlApiServer, StrataBridgeMonitoringApiServer},
    types::RpcOperatorStatus,
};
use tokio::sync::oneshot;
use tracing::{info, warn};

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

/// RPC server for the bridge node.
/// Holds a handle to the database and a copy of [`Params`].
#[derive(Clone)]
pub(crate) struct BridgeRpc {
    /// Node start time.
    start_time: DateTime<Utc>,

    /// Database handle.
    db: SqliteDb,

    /// The consensus-critical parameters that dictate the behavior of the bridge node.
    params: Params,
}

impl BridgeRpc {
    /// Create a new instance of [`BridgeRpc`].
    pub(crate) fn new(db: SqliteDb, params: Params) -> Self {
        Self {
            start_time: Utc::now(),
            db,
            params,
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
            return Err(ErrorObjectOwned::owned::<_>(
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
        // NOTE(@storopoli): We need to add a strata-p2p command to "ping" the operator.
        //       Be aware that the operator_pk here is the MuSig2 pk and you need to ping the
        //       operator by the P2P pk.
        let _ = operator_pk;
        unimplemented!()
    }

    async fn get_deposit_request_info(
        &self,
        deposit_request_outpoint: OutPoint,
    ) -> RpcResult<DepositRequestStatus> {
        let result = self
            .db
            .get_deposit_request_by_txid(deposit_request_outpoint.txid)
            .await
            .map_err(|_| {
                ErrorObjectOwned::owned::<_>(
                    -666,
                    "Database error. Config dumped",
                    Some(self.db.config()),
                )
            })?;
        match result {
            Some(deposit) => Ok(deposit),
            None => Err(ErrorObjectOwned::owned::<_>(
                -32001,
                "Deposit request outpoint not found",
                Some(deposit_request_outpoint),
            )),
        }
    }

    async fn get_bridge_duties(&self) -> RpcResult<Vec<BridgeDuty>> {
        Ok(self.db.get_all_duties().await.map_err(|_| {
            ErrorObjectOwned::owned::<_>(
                -666,
                "Database error. Config dumped",
                Some(self.db.config()),
            )
        })?)
    }

    async fn get_bridge_duties_by_operator_pk(
        &self,
        operator_pk: PublicKey,
    ) -> RpcResult<Vec<BridgeDuty>> {
        Ok(self
            .db
            .get_duties_by_operator_pk(operator_pk)
            .await
            .map_err(|_| {
                ErrorObjectOwned::owned::<_>(
                    -666,
                    "Database error. Config dumped",
                    Some(self.db.config()),
                )
            })?)
    }

    async fn get_withdrawal_info(
        &self,
        withdrawal_outpoint: OutPoint,
    ) -> RpcResult<WithdrawalStatus> {
        let withdrawal_txid = withdrawal_outpoint.txid;
        let status = self
            .db
            .get_withdrawal_by_txid(withdrawal_txid)
            .await
            .map_err(|_| {
                ErrorObjectOwned::owned::<_>(
                    -666,
                    "Database error. Config dumped",
                    Some(self.db.config()),
                )
            })?;
        match status {
            Some(status) => Ok(status),
            None => Err(ErrorObjectOwned::owned::<_>(
                -32001,
                "Withdrawal outpoint not found",
                Some(withdrawal_outpoint),
            )),
        }
    }

    async fn get_claims(&self) -> RpcResult<Vec<Txid>> {
        Ok(self.db.get_all_claims().await.map_err(|_| {
            ErrorObjectOwned::owned::<_>(
                -666,
                "Database error. Config dumped",
                Some(self.db.config()),
            )
        })?)
    }

    async fn get_claim_info(&self, claim_txid: Txid) -> RpcResult<ClaimStatus> {
        let result = self.db.get_claim_by_txid(claim_txid).await.map_err(|_| {
            ErrorObjectOwned::owned::<_>(
                -666,
                "Database error. Config dumped",
                Some(self.db.config()),
            )
        })?;
        match result {
            Some(status) => Ok(status),
            None => Err(ErrorObjectOwned::owned::<_>(
                -32001,
                "Claim not found",
                Some(claim_txid),
            )),
        }
    }
}
