//! Traits for the RPC server.

use bitcoin::{taproot::Signature, OutPoint, PublicKey, Txid};
use jsonrpsee::{core::RpcResult, proc_macros::rpc};

use crate::types::{
    RpcBridgeDutyStatus, RpcClaimInfo, RpcDepositStatus, RpcOperatorStatus, RpcWithdrawalInfo,
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

    /// Get deposit details using the deposit request outpoint.
    #[method(name = "depositInfo")]
    async fn get_deposit_request_info(
        &self,
        deposit_request_outpoint: OutPoint,
    ) -> RpcResult<RpcDepositStatus>;

    /// Get bridge duties.
    #[method(name = "bridgeDuties")]
    async fn get_bridge_duties(&self) -> RpcResult<Vec<RpcBridgeDutyStatus>>;

    /// Get bridge duties assigned to an operator by its [`PublicKey`].
    #[method(name = "bridgeDutiesByPk")]
    async fn get_bridge_duties_by_operator_pk(
        &self,
        operator_pk: PublicKey,
    ) -> RpcResult<Vec<RpcBridgeDutyStatus>>;

    /// Get withdrawal details using withdrawal outpoint.
    #[method(name = "withdrawalInfo")]
    async fn get_withdrawal_info(
        &self,
        withdrawal_outpoint: OutPoint,
    ) -> RpcResult<RpcWithdrawalInfo>;

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
    /// Query for challenge signature for a particular claim.
    #[method(name = "challengeSignature")]
    async fn get_challenge_signature(&self, claim_txid: Txid) -> RpcResult<Option<Signature>>;

    /// Query for disprove signature for a particular claim.
    #[method(name = "disproveSignature")]
    async fn get_disprove_signature(&self, claim_txid: Txid) -> RpcResult<Option<Signature>>;
}
