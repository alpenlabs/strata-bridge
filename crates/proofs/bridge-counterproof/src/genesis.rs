//! Host-only loader for [`crate::BridgeCounterproofGenesis`].

use strata_predicate::PredicateKey;

use crate::types::BridgeCounterproofGenesis;

/// Builds the bridge-counterproof genesis.
pub fn load_genesis() -> BridgeCounterproofGenesis {
    BridgeCounterproofGenesis {
        bridge_proof_vk: PredicateKey::never_accept(),
    }
}
