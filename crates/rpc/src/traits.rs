//! Traits for the RPC server.

use bitcoin::{PublicKey, Txid};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use strata_bridge_primitives::types::{DepositIdx, GraphIdx};
use strata_primitives::buf::Buf32;

use crate::types::{
    RpcAggregateSignatures, RpcBridgeDutyStatus, RpcClaimInfo, RpcDepositInfo, RpcGraphData,
    RpcOperatorStatus, RpcPendingWithdrawalInfo, RpcWithdrawalInfo,
};

/// RPCs related to information about the client itself.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "stratabridge"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "stratabridge"))]
pub trait StrataBridgeControlApi {
    /// Get the uptime for the client in seconds assuming the clock is strictly monotonically
    /// increasing.
    #[method(name = "uptime")]
    async fn get_uptime(&self) -> RpcResult<u64>;
}

/// RPCs that allow monitoring the state of the bridge, including the status of the operators,
/// deposit processing and withdrawal handling.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "stratabridge"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "stratabridge"))]
pub trait StrataBridgeMonitoringApi {
    /// Get all bridge operator IDs.
    #[method(name = "bridgeOperators")]
    async fn get_bridge_operators(&self) -> RpcResult<Vec<PublicKey>>;

    /// Query operator status (Online/Offline).
    #[method(name = "operatorStatus")]
    async fn get_operator_status(&self, operator_pk: PublicKey) -> RpcResult<RpcOperatorStatus>;

    /// Get all deposit request [`Txid`]s.
    #[method(name = "depositRequests")]
    async fn get_deposit_requests(&self) -> RpcResult<Vec<Txid>>;

    /// Get deposit details using the deposit request [`Txid`].
    #[method(name = "depositInfo")]
    async fn get_deposit_request_info(
        &self,
        deposit_request_txid: Txid,
    ) -> RpcResult<RpcDepositInfo>;

    /// Get bridge duties.
    // TODO: <https://atlassian.alpenlabs.net/browse/STR-2703>
    // Move this to a new trait; the monitoring API does not use it and it is for internal
    // debugging and introspection.
    #[method(name = "bridgeDuties")]
    async fn get_bridge_duties(&self) -> RpcResult<Vec<RpcBridgeDutyStatus>>;

    /// Get bridge duties assigned to an operator by its [`PublicKey`].
    // TODO: <https://atlassian.alpenlabs.net/browse/STR-2703>
    // Move this to a new trait; the monitoring API does not use it and it is for internal
    // debugging and introspection.
    #[method(name = "bridgeDutiesByPk")]
    async fn get_bridge_duties_by_operator_pk(
        &self,
        operator_pk: PublicKey,
    ) -> RpcResult<Vec<RpcBridgeDutyStatus>>;

    /// Get all withdrawal request txids.
    ///
    /// NOTE: These are not Bitcoin txids but [`Buf32`] representing the transaction IDs of the
    /// withdrawal transactions in the sidesystem's execution environment.
    #[method(name = "withdrawals")]
    async fn get_withdrawals(&self) -> RpcResult<Vec<Buf32>>;

    /// Get withdrawal details using withdrawal request txid.
    ///
    /// NOTE: This is not a Bitcoin txid but a [`Buf32`] representing the transaction ID of the
    /// withdrawal transaction in the sidesystem's execution environment.
    #[method(name = "withdrawalInfo")]
    async fn get_withdrawal_info(
        &self,
        withdrawal_request_txid: Buf32,
    ) -> RpcResult<Option<RpcWithdrawalInfo>>;

    /// Get all claim transaction IDs.
    #[method(name = "claims")]
    async fn get_claims(&self) -> RpcResult<Vec<Txid>>;

    /// Get claim details for a given claim transaction ID.
    #[method(name = "claimInfo")]
    async fn get_claim_info(&self, claim_txid: Txid) -> RpcResult<Option<RpcClaimInfo>>;

    /// Get the withdrawals currently being processed.
    #[method(name = "pendingWithdrawals")]
    async fn get_pending_withdrawals(&self) -> RpcResult<Vec<DepositIdx>>;

    /// Get the status of a particular withdrawal by its deposit index.
    #[method(name = "pendingWithdrawalInfo")]
    async fn get_pending_withdrawal_info(
        &self,
        deposit_idx: DepositIdx,
    ) -> RpcResult<Option<RpcPendingWithdrawalInfo>>;
}

/// RPCs required for data availability.
///
/// These RPCs make the data required to enable permissionless challenging available.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "stratabridge"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "stratabridge"))]
pub trait StrataBridgeDaApi {
    /// Query for the deposit-time graph data for a particular graph.
    #[method(name = "graphData")]
    async fn get_graph_data(&self, graph_idx: GraphIdx) -> RpcResult<Option<RpcGraphData>>;

    /// Query for the aggregate graph signatures for a particular graph.
    #[method(name = "aggregateSignatures")]
    async fn get_aggregate_signatures(
        &self,
        graph_idx: GraphIdx,
    ) -> RpcResult<Option<RpcAggregateSignatures>>;
}
