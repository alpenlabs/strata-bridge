//! Trust anchors for the bridge counterproof. Host-only.

use moho_types::StateRefAttestation;
use strata_bridge_proof::load_genesis_from_env as load_bridge_proof_genesis_from_env;
use strata_predicate::PredicateKey;

/// Trust anchors for verifying the bridge proof and Moho proofs.
#[derive(Debug, Clone)]
pub struct BridgeCounterproofGenesis {
    /// Verifying key for the bridge proof.
    pub bridge_proof_vk: PredicateKey,

    /// Verifying key for the Moho proof.
    pub moho_vk: PredicateKey,

    /// Attestation to the Moho genesis state.
    pub genesis_moho_state: StateRefAttestation,
}

/// Builds the bridge-counterproof genesis.
pub fn load_genesis() -> BridgeCounterproofGenesis {
    let bridge_proof_genesis = load_bridge_proof_genesis_from_env();

    BridgeCounterproofGenesis {
        bridge_proof_vk: PredicateKey::never_accept(),
        moho_vk: bridge_proof_genesis.moho_vk,
        genesis_moho_state: bridge_proof_genesis.genesis_moho_state,
    }
}
