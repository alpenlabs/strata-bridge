//! Trust anchors for the bridge proof's recursive Moho verification. Host-only.

use moho_runtime_interface::MohoProgram;
use moho_types::{ExportState, MohoState, StateRefAttestation, StateReference};
use strata_asm_params::AsmParams;
use strata_asm_proof_impl::moho_program::program::AsmStfProgram;
use strata_asm_spec::construct_genesis_state;
use strata_predicate::PredicateKey;

/// Path to `asm-params.json`. Must be set before calling [`load_genesis`].
pub const ASM_PARAMS_PATH_ENV: &str = "BRIDGE_PROOF_ASM_PARAMS_PATH";

/// Trust anchors used when verifying the recursive Moho proof.
#[derive(Debug, Clone)]
pub struct BridgeProofGenesis {
    /// Verifying key for the Moho proof.
    pub moho_vk: PredicateKey,

    /// Attested genesis state that the Moho transition is anchored against.
    pub genesis_moho_state: StateRefAttestation,
}

/// Builds the bridge-proof genesis from `asm-params.json` (path via [`ASM_PARAMS_PATH_ENV`]).
///
/// Both the Moho VK and ASM-STF predicate are [`PredicateKey::always_accept`] for now.
/// Swap them in once the canonical VK ships (STR-1977).
pub fn load_genesis() -> BridgeProofGenesis {
    let path = std::env::var(ASM_PARAMS_PATH_ENV).expect("{ASM_PARAMS_PATH_ENV} must be set");
    let bytes = std::fs::read(&path).expect("cannot read asm-params.json");
    let asm_params: AsmParams =
        serde_json::from_slice(&bytes).expect("asm-params.json must deserialize into AsmParams");

    let asm_predicate = PredicateKey::always_accept();
    let moho_vk = PredicateKey::always_accept();

    let anchor_state = construct_genesis_state(&asm_params);
    let inner_state = <AsmStfProgram as MohoProgram>::compute_state_commitment(&anchor_state);
    let export_state = ExportState::new(vec![]).expect("empty export state is always valid");
    let genesis_moho_state = MohoState::new(inner_state, asm_predicate, export_state);

    let blkid_bytes: [u8; 32] = *asm_params.anchor.block.blkid().as_ref();
    let state_ref = StateReference::new(blkid_bytes);
    let commitment = genesis_moho_state.compute_commitment();

    BridgeProofGenesis {
        moho_vk,
        genesis_moho_state: StateRefAttestation::new(state_ref, commitment),
    }
}
