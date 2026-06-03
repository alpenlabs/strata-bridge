//! Trust anchors for the bridge counterproof. Host-only.

use strata_bridge_proof::load_genesis_from_env as load_bridge_proof_genesis_from_env;
use strata_predicate::PredicateKey;

use crate::types::BridgeCounterproofGenesis;

/// Builds the bridge-counterproof genesis from a known bridge-proof predicate key.
pub fn load_genesis_from_predicate(bridge_proof_vk: PredicateKey) -> BridgeCounterproofGenesis {
    let bridge_proof_genesis = load_bridge_proof_genesis_from_env();

    BridgeCounterproofGenesis {
        bridge_proof_vk,
        moho_vk: bridge_proof_genesis.moho_vk,
        genesis_moho_state: bridge_proof_genesis.genesis_moho_state,
    }
}

/// Builds the bridge-counterproof genesis from process environment.
pub fn load_genesis() -> BridgeCounterproofGenesis {
    load_genesis_from_predicate(PredicateKey::never_accept())
}
