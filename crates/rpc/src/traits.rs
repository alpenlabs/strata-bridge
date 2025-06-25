//! Traits for the RPC server.

use bitcoin::{taproot::Signature, PublicKey, Transaction, Txid};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use strata_primitives::buf::Buf32;

use crate::types::{
    RpcBridgeDutyStatus, RpcClaimInfo, RpcDepositInfo, RpcDisproveData, RpcOperatorStatus,
    RpcWithdrawalInfo,
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

    /// Get all deposit request outpoints.
    #[method(name = "depositRequests")]
    async fn get_deposit_requests(&self) -> RpcResult<Vec<Txid>>;

    /// Get deposit details using the deposit request outpoint.
    #[method(name = "depositInfo")]
    async fn get_deposit_request_info(
        &self,
        deposit_request_txid: Txid,
    ) -> RpcResult<RpcDepositInfo>;

    /// Get bridge duties.
    // TODO: refactor this to a new trait since the monitoring API does not use it
    //       but we'll use it internally for debugging and introspection.
    #[method(name = "bridgeDuties")]
    async fn get_bridge_duties(&self) -> RpcResult<Vec<RpcBridgeDutyStatus>>;

    /// Get bridge duties assigned to an operator by its [`PublicKey`].
    // TODO: refactor this to a new trait since the monitoring API does not use it
    //       but we'll use it internally for debugging and introspection.
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
}

/// RPCs required for data availability.
///
/// These RPCs make the data required to enable permissionless challenging available.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "stratabridge"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "stratabridge"))]
pub trait StrataBridgeDaApi {
    /// Query for the unfunded challenge transaction for a particular claim.
    #[method(name = "challengeTransaction")]
    async fn get_challenge_tx(&self, claim_txid: Txid) -> RpcResult<Option<Transaction>>;

    /// Query for challenge signature for a particular claim.
    #[method(name = "challengeSignature")]
    async fn get_challenge_signature(&self, claim_txid: Txid) -> RpcResult<Option<Signature>>;

    /// Query for the graph-setup data required to construct a disprove transaction for a particular
    /// claim.
    ///
    /// This does not include the actual disprove script, which is only known at disprove time.
    #[method(name = "disproveData")]
    async fn get_disprove_data(&self, claim_txid: Txid) -> RpcResult<Option<RpcDisproveData>>;
}
