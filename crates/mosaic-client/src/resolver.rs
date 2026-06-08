use async_trait::async_trait;
use strata_bridge_primitives::types::{GameIndex, OperatorIdx};
use strata_mosaic_client_api::MosaicError;

/// Identify a mosaic node using their network id.
pub type PeerId = [u8; 32];
/// Identify a game on mosaic.
pub type GameId = [u8; 32];
/// Pubkey as bytes.
pub type PubkeyBytes = [u8; 32];

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
    ) -> Result<PubkeyBytes, MosaicError>;

    /// Resolve game index to its mosaic game id.
    /// Default: copies game index as be bytes.
    fn resolve_game_id(&self, game_idx: GameIndex) -> GameId {
        let mut game_id = [0u8; 32];
        game_id[28..].copy_from_slice(&game_idx.get().to_be_bytes());
        game_id
    }
}
