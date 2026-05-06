//! Bridge proof statements.

use moho_recursive_proof::MohoRecursiveOutput;
use moho_types::{ExportContainer, MohoState, RecursiveMohoProof};
use ssz::Encode;
use strata_asm_proto_bridge_v1::OperatorClaimUnlock;
use strata_asm_proto_bridge_v1_txs::BRIDGE_V1_SUBPROTOCOL_ID;
use strata_codec::decode_buf_exact;
use strata_merkle::MerkleProofB32;
use zkaleido::{ZkVmEnv, ZkVmEnvSsz};

use crate::{
    errors::BridgeProofVerificationError,
    genesis::{BridgeProofGenesis, load_genesis},
    types::{BridgeProofInput, BridgeProofOutput},
};

/// zkVM entry point: loads genesis and runs the bridge proof.
pub fn process_bridge_proof(zkvm: &impl ZkVmEnv) {
    let genesis = load_genesis();
    process_bridge_proof_inner(zkvm, &genesis);
}

/// Reads the SSZ input, verifies it against `genesis`, and commits the output.
fn process_bridge_proof_inner(zkvm: &impl ZkVmEnv, genesis: &BridgeProofGenesis) {
    let BridgeProofInput {
        moho_state,
        moho_proof,
        claim_unlock,
        claim_unlock_inclusion_proof,
    } = zkvm.read_ssz();
    let claim_unlock_typed: OperatorClaimUnlock =
        decode_buf_exact(&claim_unlock).expect("claim_unlock must decode into OperatorClaimUnlock");

    // 1: Verify the recursive Moho proof.
    verify_moho_proof(&moho_state, &moho_proof, genesis);

    let bridge_container = moho_state
        .export_state()
        .containers()
        .iter()
        .find(|c| c.container_id() == BRIDGE_V1_SUBPROTOCOL_ID)
        .expect("moho_state must contain a bridge-v1 export container");

    // 2: Verify the operator claim is included in the bridge-v1 MMR.
    verify_claim_unlock_inclusion(
        &claim_unlock_typed,
        bridge_container,
        &claim_unlock_inclusion_proof,
    )
    .expect("claim_unlock must be included in the bridge-v1 MMR");

    // 3: Commit public values.
    zkvm.commit_ssz(&BridgeProofOutput {
        total_pow: bridge_container.extra_data.0,
        claim_unlock,
        mmr_idx: claim_unlock_inclusion_proof.index() as u32,
    });
}

/// Verifies the Moho proof against the bridge genesis params.
fn verify_moho_proof(
    moho_state: &MohoState,
    moho_proof: &RecursiveMohoProof,
    genesis: &BridgeProofGenesis,
) {
    let attestation = moho_proof.attestation();

    // In stub mode the MohoState commitment depends on the ASM runner's ephemeral Schnorr key
    // (generated fresh per process), so only the StateReference (anchor block ID) is stable
    // enough to compare. Full commitment verification is gated behind STR-1977.
    assert_eq!(
        attestation.genesis().reference(),
        genesis.genesis_moho_state.reference(),
        "moho proof genesis reference does not match bridge's anchor block",
    );
    assert_eq!(
        attestation.proven().commitment(),
        &moho_state.compute_commitment(),
        "moho proof proven commitment does not match the supplied moho_state",
    );

    // Claim encoding: SSZ(MohoRecursiveOutput { attestation, moho_vk }).
    // With always_accept this is a no-op; swapping in the real VK (STR-1977) makes it binding.
    let claim =
        MohoRecursiveOutput::new(attestation.clone(), genesis.moho_vk.clone()).as_ssz_bytes();
    genesis
        .moho_vk
        .verify_claim_witness(&claim, moho_proof.proof())
        .expect("moho proof verification failed");
}

/// Verifies that `claim_unlock` is included in `bridge_container`'s entries MMR.
fn verify_claim_unlock_inclusion(
    claim_unlock: &OperatorClaimUnlock,
    bridge_container: &ExportContainer,
    proof: &MerkleProofB32,
) -> Result<(), BridgeProofVerificationError> {
    let leaf_hash = claim_unlock.compute_hash();
    if !bridge_container.entries_mmr().verify(proof, &leaf_hash) {
        return Err(BridgeProofVerificationError::InvalidInclusionProof);
    }
    Ok(())
}
