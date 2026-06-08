use std::num::NonZero;

use async_trait::async_trait;
use mosaic_rpc_types::RpcDepositId;
use strata_bridge_primitives::types::{GameIndex, OperatorIdx};
use strata_mosaic_client_api::MosaicError;

/// Identify a mosaic node using their network id.
pub type PeerId = [u8; 32];
/// Identify a game on mosaic.
pub type GameId = [u8; 32];
/// Pubkey as bytes.
pub type PubkeyBytes = [u8; 32];

/// Decodes a mosaic [`RpcDepositId`] into a bridge [`GameIndex`].
//
// TODO(STR-3754): drop this once mosaic exposes `game_index: u32` directly.
// https://alpenlabs.atlassian.net/browse/STR-3754
pub trait RpcDepositIdExt {
    /// Inverse of [`MosaicIdResolver::resolve_game_id`]'s default encoding.
    /// Panics if the encoded `u32` is zero.
    fn into_game_index(self) -> GameIndex;
}

impl RpcDepositIdExt for RpcDepositId {
    fn into_game_index(self) -> GameIndex {
        let bytes: [u8; 32] = self.into();
        let raw = u32::from_be_bytes(
            bytes[28..32]
                .try_into()
                .expect("slice of 4 bytes is a [u8; 4]"),
        );
        GameIndex::from_nonzero(NonZero::new(raw).expect("mosaic invariant: game index is nonzero"))
    }
}

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
