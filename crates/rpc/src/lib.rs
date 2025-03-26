//! Provides bridge-related APIs for the RPC server.
//!
//! Provides high-level traits that form the RPC interface of the Bridge. The RPCs have been
//! decomposed into various groups partly based on how bitcoin RPCs are categorized into various
//! [groups](https://developer.bitcoin.org/reference/rpc/index.html).

mod types;

use bitcoin::{OutPoint, PublicKey, Txid};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use strata_bridge_primitives::{
    duties::BridgeDuty,
    types::{OperatorIdx, PublickeyTable},
};

use crate::types::*;

/// RPCs related to information about the client itself.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "stratabridge"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "stratabridge"))]
pub trait StrataBridgeControlApi {
    /// Get the uptime for the client in seconds assuming the clock is strictly monotonically
    /// increasing.
    #[method(name = "uptime")]
    async fn get_uptime(&self) -> RpcResult<u64>;
}

#[cfg_attr(not(feature = "client"), rpc(server, namespace = "stratabridge"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "stratabridge"))]
pub trait StrataBridgeMonitoringApi {
    /// Get all bridge operator IDs.
    #[method(name = "bridgeOperators")]
    async fn get_bridge_operators(&self) -> RpcResult<PublickeyTable>;

    /// Query operator status (Online/Offline).
    #[method(name = "operatorStatus")]
    async fn get_operator_status(&self, operator_idx: OperatorIdx) -> RpcResult<RpcOperatorStatus>;

    /// Get deposit details using the deposit outpoint.
    #[method(name = "depositInfo")]
    async fn get_deposit_info(&self, deposit_outpoint: OutPoint) -> RpcResult<RpcDepositInfo>;

    /// Get bridge duties.
    #[method(name = "bridgeDuties")]
    async fn get_bridge_duties(&self) -> RpcResult<Vec<BridgeDuty>>;

    /// Get bridge duties assigned to an operator by its [`PublicKey`].
    #[method(name = "bridgeDutiesByPk")]
    async fn get_bridge_duties_by_operator_pk(
        &self,
        operator_pk: PublicKey,
    ) -> RpcResult<Vec<BridgeDuty>>;

    /// Get bridge duties assigned to an operator by [`OperatorIdx`].
    #[method(name = "bridgeDutiesById")]
    async fn get_bridge_duties_by_operator_id(
        &self,
        operator_id: OperatorIdx,
    ) -> RpcResult<Vec<BridgeDuty>>;

    /// Get withdrawal details using deposit outpoint.
    #[method(name = "withdrawalInfo")]
    async fn get_withdrawal_info(&self, deposit_outpoint: OutPoint)
        -> RpcResult<RpcWithdrawalInfo>;

    /// Get all claim transaction IDs.
    #[method(name = "claims")]
    async fn get_claims(&self) -> RpcResult<Vec<Txid>>;

    /// Get claim details for a given claim transaction ID.
    #[method(name = "claimInfo")]
    async fn get_claim_info(&self, claim_txid: Txid) -> RpcResult<RpcClaimInfo>;
}
