use async_trait::async_trait;
use bitcoin::{XOnlyPublicKey, secp256k1::schnorr::Signature as SchnorrSignature};
use mosaic_rpc_types::{
    CacRole, DepositStatus, EvaluatorDepositConfig, EvaluatorWithdrawalConfig,
    GarblerDepositConfig, RpcByte32, RpcCompletedSignatures, RpcDepositId, RpcInstanceId,
    RpcPeerId, RpcSetupConfig, RpcTablesetId, RpcTablesetStatus, RpcWithdrawalInputs,
};

/// Abstraction over the mosaic JSON-RPC interface.
///
/// Each method maps 1:1 to a method on the mosaic RPC server.
/// The blanket implementation for [`jsonrpsee::http_client::HttpClient`]
/// delegates to the generated [`mosaic_rpc_api::MosaicRpcClient`] trait.
#[async_trait]
pub trait MosaicApi: Send + Sync + 'static {
    /// The error type returned by RPC calls.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Get deterministic [`RpcTablesetId`] for a given role, peer and instance.
    async fn get_tableset_id(
        &self,
        role: CacRole,
        peer_id: RpcPeerId,
        instance: RpcInstanceId,
    ) -> Result<RpcTablesetId, Self::Error>;

    /// Initiate tableset setup for a pair of mosaic clients.
    async fn setup_tableset(&self, config: RpcSetupConfig) -> Result<RpcTablesetId, Self::Error>;

    /// Get current setup status of a tableset.
    async fn get_tableset_status(
        &self,
        tsid: RpcTablesetId,
    ) -> Result<Option<RpcTablesetStatus>, Self::Error>;

    /// Get pubkey for the fault secret encoded in the garbling tables.
    async fn get_fault_secret_pubkey(
        &self,
        tsid: RpcTablesetId,
    ) -> Result<Option<XOnlyPublicKey>, Self::Error>;

    /// Get adaptor pubkey for an evaluator tableset deposit.
    async fn evaluator_get_adaptor_pubkey(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> Result<Option<XOnlyPublicKey>, Self::Error>;

    /// Create a deposit instance on a garbler tableset.
    async fn init_garbler_deposit(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        deposit: GarblerDepositConfig,
    ) -> Result<(), Self::Error>;

    /// Create a deposit instance on an evaluator tableset.
    async fn init_evaluator_deposit(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        deposit: EvaluatorDepositConfig,
    ) -> Result<(), Self::Error>;

    /// Get deposit status on a given tableset.
    async fn get_deposit_status(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> Result<Option<DepositStatus>, Self::Error>;

    /// Mark a deposit as withdrawn without contest.
    async fn mark_deposit_withdrawn(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> Result<(), Self::Error>;

    /// Mark a contested withdrawal and compute adaptor signatures (garbler only).
    async fn complete_adaptor_sigs(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        inputs: RpcWithdrawalInputs,
    ) -> Result<(), Self::Error>;

    /// Get adaptor signatures computed after a contested withdrawal (garbler only).
    async fn get_completed_adaptor_sigs(
        &self,
        tsid: RpcTablesetId,
    ) -> Result<RpcCompletedSignatures, Self::Error>;

    /// Initiate tableset evaluation with completed adaptor signatures (evaluator only).
    async fn evaluate_tableset(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        inputs: EvaluatorWithdrawalConfig,
    ) -> Result<(), Self::Error>;

    /// Sign data using the extracted fault secret after evaluation (evaluator only).
    async fn sign_with_fault_secret(
        &self,
        tsid: RpcTablesetId,
        digest: RpcByte32,
        tweak: Option<RpcByte32>,
    ) -> Result<Option<SchnorrSignature>, Self::Error>;
}

#[async_trait]
impl MosaicApi for jsonrpsee::http_client::HttpClient {
    type Error = jsonrpsee::core::ClientError;

    async fn get_tableset_id(
        &self,
        role: CacRole,
        peer_id: RpcPeerId,
        instance: RpcInstanceId,
    ) -> Result<RpcTablesetId, Self::Error> {
        mosaic_rpc_api::MosaicRpcClient::get_tableset_id(self, role, peer_id, instance).await
    }

    async fn setup_tableset(&self, config: RpcSetupConfig) -> Result<RpcTablesetId, Self::Error> {
        mosaic_rpc_api::MosaicRpcClient::setup_tableset(self, config).await
    }

    async fn get_tableset_status(
        &self,
        tsid: RpcTablesetId,
    ) -> Result<Option<RpcTablesetStatus>, Self::Error> {
        mosaic_rpc_api::MosaicRpcClient::get_tableset_status(self, tsid).await
    }

    async fn get_fault_secret_pubkey(
        &self,
        tsid: RpcTablesetId,
    ) -> Result<Option<XOnlyPublicKey>, Self::Error> {
        mosaic_rpc_api::MosaicRpcClient::get_fault_secret_pubkey(self, tsid).await
    }

    async fn evaluator_get_adaptor_pubkey(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> Result<Option<XOnlyPublicKey>, Self::Error> {
        mosaic_rpc_api::MosaicRpcClient::evaluator_get_adaptor_pubkey(self, tsid, deposit_id).await
    }

    async fn init_garbler_deposit(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        deposit: GarblerDepositConfig,
    ) -> Result<(), Self::Error> {
        mosaic_rpc_api::MosaicRpcClient::init_garbler_deposit(self, tsid, deposit_id, deposit).await
    }

    async fn init_evaluator_deposit(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        deposit: EvaluatorDepositConfig,
    ) -> Result<(), Self::Error> {
        mosaic_rpc_api::MosaicRpcClient::init_evaluator_deposit(self, tsid, deposit_id, deposit)
            .await
    }

    async fn get_deposit_status(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> Result<Option<DepositStatus>, Self::Error> {
        mosaic_rpc_api::MosaicRpcClient::get_deposit_status(self, tsid, deposit_id).await
    }

    async fn mark_deposit_withdrawn(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
    ) -> Result<(), Self::Error> {
        mosaic_rpc_api::MosaicRpcClient::mark_deposit_withdrawn(self, tsid, deposit_id).await
    }

    async fn complete_adaptor_sigs(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        inputs: RpcWithdrawalInputs,
    ) -> Result<(), Self::Error> {
        mosaic_rpc_api::MosaicRpcClient::complete_adaptor_sigs(self, tsid, deposit_id, inputs).await
    }

    async fn get_completed_adaptor_sigs(
        &self,
        tsid: RpcTablesetId,
    ) -> Result<RpcCompletedSignatures, Self::Error> {
        mosaic_rpc_api::MosaicRpcClient::get_completed_adaptor_sigs(self, tsid).await
    }

    async fn evaluate_tableset(
        &self,
        tsid: RpcTablesetId,
        deposit_id: RpcDepositId,
        inputs: EvaluatorWithdrawalConfig,
    ) -> Result<(), Self::Error> {
        mosaic_rpc_api::MosaicRpcClient::evaluate_tableset(self, tsid, deposit_id, inputs).await
    }

    async fn sign_with_fault_secret(
        &self,
        tsid: RpcTablesetId,
        digest: RpcByte32,
        tweak: Option<RpcByte32>,
    ) -> Result<Option<SchnorrSignature>, Self::Error> {
        mosaic_rpc_api::MosaicRpcClient::sign_with_fault_secret(self, tsid, digest, tweak).await
    }
}
