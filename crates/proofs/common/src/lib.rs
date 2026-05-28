//! Shared proving primitives reused by every per-program proof crate
//! (e.g. `strata-bridge-proof`).

use moho_recursive_proof::MohoRecursiveOutput;
use moho_types::{ExportContainer, MohoState, RecursiveMohoProof, StateReference};
use ssz::Encode;
use strata_asm_proto_bridge_v1::OperatorClaimUnlock;
use strata_merkle::MerkleProofB32;
use strata_predicate::PredicateKey;
use thiserror::Error;
use tokio::task::JoinError;
use zkaleido::{ProofReceipt, ZkVmError, ZkVmExecutor, ZkVmHost, ZkVmInputBuilder, ZkVmProgram};

/// Errors returned by [`prove`].
#[derive(Debug, Error)]
pub enum ProofError {
    /// Proving inside the zkVM (or its native adapter) failed.
    #[error("zkvm proving failed: {0}")]
    ZkVm(#[from] ZkVmError),

    /// The blocking proving task panicked or was cancelled.
    #[error("proving task join error: {0}")]
    Join(#[from] JoinError),
}

/// Generates a proof for `P` using `host`.
pub async fn prove<P, H>(input: P::Input, host: H) -> Result<ProofReceipt, ProofError>
where
    P: ZkVmProgram + 'static,
    P::Input: Send + 'static,
    P::Output: 'static,
    H: ZkVmHost + Clone + Send + Sync + 'static,
    for<'a> <H as ZkVmExecutor>::Input<'a>: ZkVmInputBuilder<'a>,
{
    let receipt_with_meta = tokio::task::spawn_blocking(move || P::prove(&input, &host)).await??;
    Ok(receipt_with_meta.receipt().clone())
}

/// Asserts that `claim_unlock` is present in the bridge-v1 export-entries
/// Merkle mountain range by verifying the `inclusion_proof`.
///
/// # Panics
///
/// This function panics if the inclusion proof is invalid.
pub fn verify_claim_unlock_inclusion(
    claim_unlock: &OperatorClaimUnlock,
    bridge_container: &ExportContainer,
    inclusion_proof: &MerkleProofB32,
) {
    let leaf_hash = claim_unlock.compute_hash();
    assert!(
        bridge_container
            .entries_mmr()
            .verify(inclusion_proof, &leaf_hash),
        "claim_unlock must be included in the bridge-v1 MMR",
    );
}

/// Verifies a recursive Moho proof against the supplied trusted genesis
/// reference and verifier key.
///
/// # Panics
///
/// This function panics if the Moho proof is invalid.
pub fn verify_moho_proof(
    moho_state: &MohoState,
    moho_proof: &RecursiveMohoProof,
    moho_genesis: &StateReference,
    moho_vk: PredicateKey,
) {
    let attestation = moho_proof.attestation();

    assert_eq!(
        attestation.genesis().reference(),
        moho_genesis,
        "moho proof genesis reference does not match bridge's anchor block",
    );
    assert_eq!(
        attestation.proven().commitment(),
        &moho_state.compute_commitment(),
        "moho proof proven commitment does not match the supplied moho_state",
    );

    let claim = MohoRecursiveOutput::new(attestation.clone(), moho_vk.clone()).as_ssz_bytes();
    moho_vk
        .verify_claim_witness(&claim, moho_proof.proof())
        .expect("moho proof verification failed");
}
