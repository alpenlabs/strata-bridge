//! Trust anchors for the bridge counterproof. Host-only.

use strata_predicate::PredicateKey;

/// Trust anchors for verifying the embedded bridge proof.
#[derive(Debug, Clone)]
pub struct BridgeCounterproofGenesis {
    /// Verifying key for the bridge proof — mirrors bridge-proof's `moho_vk` abstraction.
    pub bridge_proof_vk: PredicateKey,
}

/// Builds the bridge-counterproof genesis.
pub fn load_genesis() -> BridgeCounterproofGenesis {
    BridgeCounterproofGenesis {
        bridge_proof_vk: PredicateKey::never_accept(),
    }
}
