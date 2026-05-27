//! Host-only loaders for [`crate::BridgeCounterproofGenesis`].

use strata_predicate::PredicateKey;

use crate::types::BridgeCounterproofGenesis;

/// Builds the bridge-counterproof genesis from a known bridge-proof vkey.
pub const fn load_genesis_from_predicate(
    bridge_proof_vk: PredicateKey,
) -> BridgeCounterproofGenesis {
    BridgeCounterproofGenesis { bridge_proof_vk }
}

/// Builds the bridge-counterproof genesis from process environment.
pub fn load_genesis_from_env() -> BridgeCounterproofGenesis {
    load_genesis_from_predicate(PredicateKey::never_accept())
}
