//! Traits for the RPC server.

use bitcoin::PublicKey;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx};

use crate::types::{
    RpcAggregateSignatures, RpcBridgeDutyStatus, RpcDepositInfo, RpcGraphData,
    RpcOperatorStakeInfo, RpcOperatorStatus, RpcPendingWithdrawalInfo, RpcReimbursementStatus,
    RpcStakeAggregateSignatures, RpcStakeData, RpcWithdrawalStatus,
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

    /// Get all known deposit indices.
    #[method(name = "depositIndices")]
    async fn get_deposit_indices(&self) -> RpcResult<Vec<DepositIdx>>;

    /// Get deposit details using the deposit index.
    #[method(name = "depositInfo")]
    async fn get_deposit_info(&self, deposit_idx: DepositIdx) -> RpcResult<RpcDepositInfo>;

    /// Get bridge duties.
    // TODO: <https://alpenlabs.atlassian.net/browse/STR-2703>
    // Move this to a new trait; the monitoring API does not use it and it is for internal
    // debugging and introspection.
    #[method(name = "bridgeDuties")]
    async fn get_bridge_duties(&self) -> RpcResult<Vec<RpcBridgeDutyStatus>>;

    /// Get bridge duties assigned to an operator by its [`PublicKey`].
    // TODO: <https://alpenlabs.atlassian.net/browse/STR-2703>
    // Move this to a new trait; the monitoring API does not use it and it is for internal
    // debugging and introspection.
    #[method(name = "bridgeDutiesByPk")]
    async fn get_bridge_duties_by_operator_pk(
        &self,
        operator_pk: PublicKey,
    ) -> RpcResult<Vec<RpcBridgeDutyStatus>>;

    /// Get the status of a withdrawal by its deposit index.
    #[method(name = "withdrawalStatus")]
    async fn get_withdrawal_status(
        &self,
        deposit_idx: DepositIdx,
    ) -> RpcResult<Option<RpcWithdrawalStatus>>;

    /// Get the reimbursement status for a withdrawal by its deposit index.
    #[method(name = "reimbursementStatus")]
    async fn get_reimbursement_status(
        &self,
        deposit_idx: DepositIdx,
    ) -> RpcResult<Option<RpcReimbursementStatus>>;

    /// Get the withdrawals currently being processed.
    #[method(name = "pendingWithdrawals")]
    async fn get_pending_withdrawals(&self) -> RpcResult<Vec<DepositIdx>>;

    /// Get the status of a particular withdrawal by its deposit index.
    #[method(name = "pendingWithdrawalInfo")]
    async fn get_pending_withdrawal_info(
        &self,
        deposit_idx: DepositIdx,
    ) -> RpcResult<Option<RpcPendingWithdrawalInfo>>;

    /// Get the stake status for every operator the node is tracking.
    #[method(name = "stakeStatus")]
    async fn get_stake_status(&self) -> RpcResult<Vec<RpcOperatorStakeInfo>>;

    /// Get the latched safe-harbour address as a hex-encoded BOSD descriptor, or `None` if
    /// this node has not observed a safe-harbour activation.
    #[method(name = "safeHarbourAddress")]
    async fn get_safe_harbour_address(&self) -> RpcResult<Option<String>>;
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

    /// Query for the setup data required to reconstruct an operator's stake graph.
    #[method(name = "stakeData")]
    async fn get_stake_data(&self, operator_idx: OperatorIdx) -> RpcResult<Option<RpcStakeData>>;

    /// Query for the aggregate stake signatures for a particular operator.
    #[method(name = "stakeAggregateSignatures")]
    async fn get_stake_aggregate_signatures(
        &self,
        operator_idx: OperatorIdx,
    ) -> RpcResult<Option<RpcStakeAggregateSignatures>>;
}
