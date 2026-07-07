//! Trust anchors for the bridge counterproof. Host-only.

use std::path::Path;

use strata_bridge_proof::{
    BridgeProofGenesis, load_genesis_from_env as load_bridge_proof_genesis_from_env,
    load_genesis_from_paths as load_bridge_proof_genesis_from_paths,
};
use strata_predicate::PredicateKey;

use crate::types::BridgeCounterproofGenesis;

/// Builds a [`BridgeCounterproofGenesis`] directly from file paths and a known bridge-proof
/// verifying key.
pub fn load_genesis_from_paths(
    bridge_proof_vk: PredicateKey,
    asm_params_path: &Path,
    asm_vk_path: &Path,
    moho_vk_path: &Path,
) -> BridgeCounterproofGenesis {
    let bridge_proof_genesis =
        load_bridge_proof_genesis_from_paths(asm_params_path, asm_vk_path, moho_vk_path);
    from_bridge_proof_genesis(bridge_proof_vk, bridge_proof_genesis)
}

/// Builds a [`BridgeCounterproofGenesis`] from a known bridge-proof predicate key, with Moho
/// anchors from paths supplied via [`strata_bridge_proof::ASM_PARAMS_PATH_ENV`],
/// [`strata_bridge_proof::ASM_VK_PATH_ENV`], and [`strata_bridge_proof::MOHO_VK_PATH_ENV`]
/// (all required).
pub fn load_genesis_from_predicate(bridge_proof_vk: PredicateKey) -> BridgeCounterproofGenesis {
    from_bridge_proof_genesis(bridge_proof_vk, load_bridge_proof_genesis_from_env())
}

/// Builds a [`BridgeCounterproofGenesis`] from process environment, with a never-accept
/// bridge-proof predicate.
pub fn load_genesis() -> BridgeCounterproofGenesis {
    load_genesis_from_predicate(PredicateKey::never_accept())
}

/// Wraps a [`BridgeProofGenesis`] with the bridge-proof verifying key to form the counterproof's
/// trust anchors.
fn from_bridge_proof_genesis(
    bridge_proof_vk: PredicateKey,
    bridge_proof_genesis: BridgeProofGenesis,
) -> BridgeCounterproofGenesis {
    BridgeCounterproofGenesis {
        bridge_proof_vk,
        moho_vk: bridge_proof_genesis.moho_vk,
        genesis_moho_state: bridge_proof_genesis.genesis_moho_state,
    }
}
