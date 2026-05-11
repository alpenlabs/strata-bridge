//! Host-side helpers for deriving [`crate::BridgeProofGenesis`] from on-disk JSON inputs.
//! Not invoked in the proving path.

use std::path::Path;

use moho_runtime_interface::MohoProgram;
use moho_types::{ExportState, MohoState, StateRefAttestation, StateReference};
use strata_asm_params::AsmParams;
use strata_asm_proof_impl::moho_program::program::AsmStfProgram;
use strata_asm_spec::construct_genesis_state;
use strata_predicate::PredicateKey;

use crate::types::BridgeProofGenesis;

/// Path to `asm-params.json`. Required input for [`load_genesis_from_env`].
pub const ASM_PARAMS_PATH_ENV: &str = "BRIDGE_PROOF_ASM_PARAMS_PATH";

/// Path to `moho-vk.json`. Optional input for [`load_genesis_from_env`]; when unset, the
/// Moho VK defaults to [`PredicateKey::always_accept`].
pub const MOHO_VK_PATH_ENV: &str = "BRIDGE_PROOF_MOHO_VK_PATH";

/// Builds a [`BridgeProofGenesis`] directly from file paths.
pub fn load_genesis_from_paths(
    asm_params_path: &Path,
    moho_vk_path: Option<&Path>,
) -> BridgeProofGenesis {
    let asm_bytes = read_or_panic("asm-params", asm_params_path);
    let genesis_moho_state = derive_anchor_attestation(&asm_bytes);

    let moho_vk = match moho_vk_path {
        Some(path) => parse_moho_vk_json(&read_or_panic("moho-vk", path)),
        None => PredicateKey::always_accept(),
    };

    BridgeProofGenesis {
        moho_vk,
        genesis_moho_state,
    }
}

/// Builds a [`BridgeProofGenesis`] from paths supplied via
/// [`ASM_PARAMS_PATH_ENV`] (required) and [`MOHO_VK_PATH_ENV`] (optional).
pub fn load_genesis_from_env() -> BridgeProofGenesis {
    let asm = std::env::var(ASM_PARAMS_PATH_ENV)
        .unwrap_or_else(|_| panic!("{ASM_PARAMS_PATH_ENV} must be set"));
    let vk = std::env::var_os(MOHO_VK_PATH_ENV);
    load_genesis_from_paths(Path::new(&asm), vk.as_deref().map(Path::new))
}

fn derive_anchor_attestation(bytes: &[u8]) -> StateRefAttestation {
    let asm_params: AsmParams =
        serde_json::from_slice(bytes).expect("asm-params.json must deserialize into AsmParams");

    let asm_predicate = PredicateKey::always_accept();

    let anchor_state = construct_genesis_state(&asm_params);
    let inner_state = <AsmStfProgram as MohoProgram>::compute_state_commitment(&anchor_state);
    let export_state = ExportState::new(vec![]).expect("empty export state is always valid");
    let genesis_moho_state = MohoState::new(inner_state, asm_predicate, export_state);

    let blkid_bytes: [u8; 32] = *asm_params.anchor.block.blkid().as_ref();
    let state_ref = StateReference::new(blkid_bytes);
    let commitment = genesis_moho_state.compute_commitment();

    StateRefAttestation::new(state_ref, commitment)
}

fn parse_moho_vk_json(bytes: &[u8]) -> PredicateKey {
    serde_json::from_slice(bytes)
        .expect("moho-vk.json must deserialize into PredicateKey (e.g., \"AlwaysAccept\")")
}

fn read_or_panic(label: &str, path: &Path) -> Vec<u8> {
    std::fs::read(path)
        .unwrap_or_else(|e| panic!("failed to read {label} at {}: {e}", path.display()))
}
