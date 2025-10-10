#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct BridgeProofPublicOutput {
    tip_total_work: u64,
    deposit_idx: u32,
    operator_idx: u32,
}

pub(crate) type MohoState = String;
pub(crate) type Groth16Proof = String;
pub(crate) type OperatorClaimUnlock = String;
pub(crate) type MerkleInclusionProof = String;

pub(crate) struct BridgeProofInput {
    moho_state: MohoState,
    moho_recursive_proof: Groth16Proof,
    claim_inclusion_proof: MerkleInclusionProof,
}

pub(crate) fn process_bridge_proof(input: BridgeProofInput) -> BridgeProofPublicOutput {
    BridgeProofPublicOutput::default()
}
