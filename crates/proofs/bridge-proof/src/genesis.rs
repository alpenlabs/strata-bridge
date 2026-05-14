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

/// Path to `asm-vk.json`. Required input for [`load_genesis_from_env`].
pub const ASM_VK_PATH_ENV: &str = "BRIDGE_PROOF_ASM_VK_PATH";

/// Path to `moho-vk.json`. Required input for [`load_genesis_from_env`].
pub const MOHO_VK_PATH_ENV: &str = "BRIDGE_PROOF_MOHO_VK_PATH";

/// Builds a [`BridgeProofGenesis`] directly from file paths.
pub fn load_genesis_from_paths(
    asm_params_path: &Path,
    asm_vk_path: &Path,
    moho_vk_path: &Path,
) -> BridgeProofGenesis {
    let asm_bytes = read_or_panic("asm-params", asm_params_path);
    let asm_vk = parse_predicate_json(&read_or_panic("asm-vk", asm_vk_path));
    let moho_vk = parse_predicate_json(&read_or_panic("moho-vk", moho_vk_path));

    let genesis_moho_state = derive_anchor_attestation(&asm_bytes, asm_vk);

    BridgeProofGenesis {
        moho_vk,
        genesis_moho_state,
    }
}

/// Builds a [`BridgeProofGenesis`] from paths supplied via
/// [`ASM_PARAMS_PATH_ENV`], [`ASM_VK_PATH_ENV`], and [`MOHO_VK_PATH_ENV`] (all required).
pub fn load_genesis_from_env() -> BridgeProofGenesis {
    let asm = std::env::var(ASM_PARAMS_PATH_ENV)
        .unwrap_or_else(|_| panic!("{ASM_PARAMS_PATH_ENV} must be set"));
    let asm_vk =
        std::env::var(ASM_VK_PATH_ENV).unwrap_or_else(|_| panic!("{ASM_VK_PATH_ENV} must be set"));
    let moho_vk = std::env::var(MOHO_VK_PATH_ENV)
        .unwrap_or_else(|_| panic!("{MOHO_VK_PATH_ENV} must be set"));
    load_genesis_from_paths(Path::new(&asm), Path::new(&asm_vk), Path::new(&moho_vk))
}

fn derive_anchor_attestation(bytes: &[u8], asm_predicate: PredicateKey) -> StateRefAttestation {
    let asm_params: AsmParams =
        serde_json::from_slice(bytes).expect("asm-params.json must deserialize into AsmParams");

    let anchor_state = construct_genesis_state(&asm_params);
    let inner_state = <AsmStfProgram as MohoProgram>::compute_state_commitment(&anchor_state);
    let export_state = ExportState::new(vec![]).expect("empty export state is always valid");
    let genesis_moho_state = MohoState::new(inner_state, asm_predicate, export_state);

    let blkid_bytes: [u8; 32] = *asm_params.anchor.block.blkid().as_ref();
    let state_ref = StateReference::new(blkid_bytes);
    let commitment = genesis_moho_state.compute_commitment();

    StateRefAttestation::new(state_ref, commitment)
}

fn parse_predicate_json(bytes: &[u8]) -> PredicateKey {
    serde_json::from_slice(bytes)
        .expect("failed to deserialize into PredicateKey (e.g., \"Bip340Schnorr:<hex>\")")
}

fn read_or_panic(label: &str, path: &Path) -> Vec<u8> {
    std::fs::read(path)
        .unwrap_or_else(|e| panic!("failed to read {label} at {}: {e}", path.display()))
}
