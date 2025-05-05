//! Bootstraps an RPC server for the operator.

use anyhow::{bail, Context};
use async_trait::async_trait;
use bitcoin::{OutPoint, PublicKey, Txid};
use chrono::{DateTime, Utc};
use jsonrpsee::{core::RpcResult, types::ErrorObjectOwned, RpcModule};
use libp2p::{identity::PublicKey as LibP2pPublicKey, PeerId};
use secp256k1::Parity;
use sqlx::query;
use strata_bridge_db::persistent::sqlite::SqliteDb;
use strata_bridge_rpc::{
    traits::{StrataBridgeControlApiServer, StrataBridgeMonitoringApiServer},
    types::{
        RpcBridgeDutyStatus, RpcClaimInfo, RpcDepositStatus, RpcOperatorStatus, RpcWithdrawalInfo,
    },
};
use strata_p2p::swarm::handle::P2PHandle;
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
/// Holds a handle to the database and the P2P messages; and a copy of [`Params`].
#[derive(Clone)]
pub(crate) struct BridgeRpc {
    /// Node start time.
    start_time: DateTime<Utc>,

    /// Database handle.
    db: SqliteDb,

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
        Self {
            start_time: Utc::now(),
            db,
            p2p_handle,
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
        let conversion = convert_operator_pk_to_peer_id(&self.params, &operator_pk);
        // Avoid DoS attacks by just returning an error if the public key is invalid
        if conversion.is_err() {
            return Err(ErrorObjectOwned::owned::<_>(
                -32001,
                "Invalid operator public key",
                Some(operator_pk.to_string()),
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
        // Iterate over all contract states to find the matching deposit request
        for contract_sm in self.current_state.values() {
            if deposit_request_txid == contract_sm.deposit_request_txid() {
                match contract_sm.get_state() {
                    ContractState::Requested { .. } => {
                        return Ok(RpcDepositStatus::InProgress {
                            deposit_request_txid,
                        });
                    }
                    _ => {
                        let deposit_txid = contract_sm.deposit_txid();
                        return Ok(RpcDepositStatus::Complete {
                            deposit_request_txid,
                            deposit_txid,
                        });
                    }
                }
            }
        }

        // If we are here, the deposit request outpoint was not found in the "hot state".
        // Let's check the database.
        let all_entries = query!(r#"SELECT * FROM contracts"#)
            .fetch_all(self.db.pool())
            .await
            .map_err(|_| {
                ErrorObjectOwned::owned::<_>(
                    -666,
                    "Database error. Config dumped",
                    Some(self.db.config()),
                )
            })?;

        for entry in all_entries {
            let entry_deposit_txid = if let Some(deposit_txid) = entry.deposit_txid.as_ref() {
                Txid::from_str(deposit_txid).map_err(|_| {
                    ErrorObjectOwned::owned::<_>(
                        -666,
                        "Database error. Config dumped",
                        Some(self.db.config()),
                    )
                })?
            } else {
                return Err(ErrorObjectOwned::owned::<_>(
                    -666,
                    "Database error. Config dumped",
                    Some(self.db.config()),
                ));
            };

            if entry_deposit_txid == deposit_request_txid {
                let state = bincode::deserialize::<ContractState>(&entry.state).map_err(|_| {
                    ErrorObjectOwned::owned::<_>(
                        -666,
                        "Database error. Config dumped",
                        Some(self.db.config()),
                    )
                })?;

                match state {
                    ContractState::Requested { .. } => {
                        return Ok(RpcDepositStatus::InProgress {
                            deposit_request_txid,
                        });
                    }
                    _ => {
                        let deposit_txid_str = entry.deposit_txid.as_ref().ok_or_else(|| {
                            ErrorObjectOwned::owned::<_>(
                                -666,
                                "Database error. Config dumped",
                                Some(self.db.config()),
                            )
                        })?;
                        let deposit_txid = Txid::from_str(deposit_txid_str).map_err(|_| {
                            ErrorObjectOwned::owned::<_>(
                                -666,
                                "Database error. Config dumped",
                                Some(self.db.config()),
                            )
                        })?;
                        return Ok(RpcDepositStatus::Complete {
                            deposit_request_txid,
                            deposit_txid,
                        });
                    }
                }
            }
        }
    }

    async fn get_bridge_duties(&self) -> RpcResult<Vec<RpcBridgeDutyStatus>> {
        todo!()
    }

    async fn get_bridge_duties_by_operator_pk(
        &self,
        _operator_pk: PublicKey,
    ) -> RpcResult<Vec<RpcBridgeDutyStatus>> {
        todo!()
    }

    async fn get_withdrawal_info(
        &self,
        _withdrawal_outpoint: OutPoint,
    ) -> RpcResult<RpcWithdrawalInfo> {
        todo!()
    }

    async fn get_claims(&self) -> RpcResult<Vec<Txid>> {
        todo!()
    }

    async fn get_claim_info(&self, _claim_txid: Txid) -> RpcResult<RpcClaimInfo> {
        todo!()
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
