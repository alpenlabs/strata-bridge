//! ASM STF proof statements.

use moho_runtime_impl::{compute_moho_attestation, RuntimeInput};
use ssz::{Decode, Encode};
use strata_asm_spec::StrataAsmSpec;
use zkaleido::ZkVmEnv;

use crate::moho_program::program::AsmStfProgram;

/// Processes the ASM state transition function inside the ZKVM guest.
///
/// This is the main entrypoint for the ASM STF proof. It deserializes the runtime input
/// from the ZKVM, runs the Moho runtime verification against the provided spec, and
/// commits the resulting attestation as the proof's public output.
///
/// # Note
///
/// The `spec` must be hardcoded by the outer guest program rather than read from the ZKVM input,
/// as it defines the trusted chain parameters that the proof is verified against.
pub fn process_asm_stf(zkvm: &impl ZkVmEnv, spec: &StrataAsmSpec) {
    let runtime_input_bytes = zkvm.read_buf();
    let runtime_input = RuntimeInput::from_ssz_bytes(&runtime_input_bytes)
        .expect("failed to deserialize runtime input for SSZ bytes");

    let attestation = compute_moho_attestation::<AsmStfProgram>(runtime_input, spec);

    let attestation_bytes = attestation.as_ssz_bytes();
    zkvm.commit_buf(&attestation_bytes);
}
