use async_trait::async_trait;
use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};
use strata_mosaic_client_api::MosaicError;

/// Identify a mosaic node using their network id.
pub type PeerId = [u8; 32];
/// Identify a deposit on mosaic.
pub type DepositId = [u8; 32];

/// Resolves bridge-internal indices to mosaic-native identifiers.
///
/// Implementations may source mappings from static config, a database,
/// or the operator table.
#[async_trait]
pub trait MosaicIdResolver: Send + Sync + 'static {
    /// Resolve operator index to the mosaic peer id of that operator's node.
    async fn resolve_peer_id(&self, operator_idx: OperatorIdx) -> Result<PeerId, MosaicError>;

    /// Resolve operator index to its 32-byte public key.
    async fn resolve_operator_pubkey(
        &self,
        operator_idx: OperatorIdx,
    ) -> Result<[u8; 32], MosaicError>;

    /// Resolve deposit index to its mosaic deposit id.
    /// Default: copies deposit idx as be bytes.
    fn resolve_deposit_id(&self, deposit_idx: DepositIdx) -> DepositId {
        let mut deposit_id = [0u8; 32];
        deposit_id[28..].copy_from_slice(&deposit_idx.to_be_bytes());
        deposit_id
    }
}
