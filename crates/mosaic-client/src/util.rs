use mosaic_rpc_types::{CacRole, RpcPeerInfo, RpcSetupConfig};
use strata_mosaic_client_api::types::{Role, SetupInputs};

use crate::resolver::PeerId;

/// Mosaic currently only supports 1 instance per (role, peerId)
pub(crate) const DEFAULT_INSTANCE: [u8; 32] = [0; 32];

pub(crate) const fn to_cac_role(role: Role) -> CacRole {
    match role {
        Role::Evaluator => CacRole::Evaluator,
        Role::Garbler => CacRole::Garbler,
    }
}

/// Create [`RpcSetupConfig`] for initializing mosaic setup.
pub(crate) fn make_setup_config(
    peer_id: PeerId,
    role: Role,
    setup_inputs: SetupInputs,
) -> RpcSetupConfig {
    RpcSetupConfig {
        role: to_cac_role(role),
        peer_info: RpcPeerInfo {
            peer_id: peer_id.into(),
        },
        setup_inputs: setup_inputs.into(),
        instance_id: DEFAULT_INSTANCE.into(),
    }
}
