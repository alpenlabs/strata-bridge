//! Bridge proof statements.

use moho_recursive_proof::MohoRecursiveOutput;
use moho_types::{MohoState, RecursiveMohoAttestation, StateRefAttestation, StateReference};
use ssz::ssz_encode;
use strata_asm_proto_bridge_v1::OperatorClaimUnlock;
use strata_asm_proto_bridge_v1_txs::BRIDGE_V1_SUBPROTOCOL_ID;
use strata_codec::decode_buf_exact;
use strata_merkle::MerkleProofB32;
use strata_predicate::PredicateKey;
use zkaleido::{ZkVmEnv, ZkVmEnvSsz};

use crate::{
    errors::BridgeProofVerificationError,
    types::{BridgeProofInput, BridgeProofOutput},
};

/// Entry point for the bridge proof zkVM program.
///
/// Reads an SSZ-encoded [`BridgeProofInput`] from the host, runs
/// [`verify_and_extract`], and commits the resulting [`BridgeProofOutput`]
/// back to the zkVM.
///
/// # Panics
///
/// Panics if the input fails to decode or any verification step rejects the
/// proof.
pub fn process_bridge_proof(zkvm: &impl ZkVmEnv) {
    let input: BridgeProofInput = zkvm.read_ssz();
    let output = verify_and_extract(input).expect("failed to verify bridge proof");
    zkvm.commit_ssz(&output);
}

/// Verifies the proof inputs and returns the bridge-proof public values.
///
/// The checks run in order:
/// 1. The recursive Moho proof attests to the `genesis_moho_state -> proven_state(moho_state)`
///    transition under the fixed verifying key.
/// 2. `claim_unlock` is included in the bridge-v1 export-entries MMR carried by `moho_state`.
///
/// On success, returns `(total_pow, claim_unlock, mmr_idx)` as the public
/// output.
pub fn verify_and_extract(
    input: BridgeProofInput,
) -> Result<BridgeProofOutput, BridgeProofVerificationError> {
    let BridgeProofInput {
        moho_state,
        moho_proof,
        claim_unlock,
        claim_unlock_inclusion_proof,
    } = input;

    let claim_unlock_typed: OperatorClaimUnlock = decode_buf_exact(&claim_unlock)
        .map_err(BridgeProofVerificationError::InvalidClaimUnlock)?;

    // 1: Verify the recursive Moho proof.
    verify_moho_proof(&moho_state, &moho_proof)?;

    // 2: Verify the operator claim is included in the moho state's bridge-v1 MMR.
    verify_claim_unlock_inclusion(
        &moho_state,
        &claim_unlock_typed,
        &claim_unlock_inclusion_proof,
    )?;

    // 3: Extract public values.
    Ok(BridgeProofOutput {
        total_pow: extract_total_pow(&moho_state),
        claim_unlock,
        mmr_idx: claim_unlock_inclusion_proof.index() as u32,
    })
}

/// Verifies the recursive Moho proof for the
/// [`genesis_moho_state`] → [`proven_state`] transition under [`moho_vk`].
fn verify_moho_proof(
    moho_state: &MohoState,
    moho_proof: &[u8],
) -> Result<(), BridgeProofVerificationError> {
    let moho_vk = moho_vk();
    let attestation = RecursiveMohoAttestation::new(genesis_moho_state(), proven_state(moho_state));
    let claim = ssz_encode(&MohoRecursiveOutput::new(attestation, moho_vk.clone()));
    moho_vk
        .verify_claim_witness(&claim, moho_proof)
        .map_err(BridgeProofVerificationError::InvalidMohoProof)
}

/// Verifies that `claim_unlock` is included in the bridge-v1 export-entries
/// MMR carried by `moho_state`.
fn verify_claim_unlock_inclusion(
    moho_state: &MohoState,
    claim_unlock: &OperatorClaimUnlock,
    proof: &MerkleProofB32,
) -> Result<(), BridgeProofVerificationError> {
    let bridge_container = moho_state
        .export_state()
        .containers()
        .iter()
        .find(|c| c.container_id() == BRIDGE_V1_SUBPROTOCOL_ID)
        .ok_or(BridgeProofVerificationError::MissingBridgeContainer)?;
    let leaf_hash = claim_unlock.compute_hash();
    if !bridge_container.entries_mmr().verify(proof, &leaf_hash) {
        return Err(BridgeProofVerificationError::InvalidInclusionProof);
    }
    Ok(())
}

/// The verifying key for the recursive Moho proof.
///
/// Currently returns [`PredicateKey::always_accept`] as a placeholder.
///
/// TODO: <https://alpenlabs.atlassian.net/browse/STR-1977>
/// Swap in the canonical `MOHO_VK` once it is published.
fn moho_vk() -> PredicateKey {
    PredicateKey::always_accept()
}

/// The genesis end of the recursive Moho transition.
///
/// Currently returns an attestation built from default values; the real
/// `GENESIS_MOHO_STATE` will replace this once published.
///
/// TODO: <https://alpenlabs.atlassian.net/browse/STR-1977>
fn genesis_moho_state() -> StateRefAttestation {
    StateRefAttestation::new(StateReference::default(), Default::default())
}

/// The proven end of the recursive Moho transition.
///
/// The commitment is taken from `moho_state`. The [`StateReference`] is a
/// placeholder until the proof anchor's reference is plumbed through
/// [`BridgeProofInput`].
///
/// TODO: <https://alpenlabs.atlassian.net/browse/STR-1977>
fn proven_state(moho_state: &MohoState) -> StateRefAttestation {
    StateRefAttestation::new(StateReference::default(), moho_state.compute_commitment())
}

/// The total accumulated proof-of-work attested by `moho_state`.
/// TODO: <https://alpenlabs.atlassian.net/browse/STR-1977>
const fn extract_total_pow(_moho_state: &MohoState) -> [u8; 32] {
    [0u8; 32]
}
