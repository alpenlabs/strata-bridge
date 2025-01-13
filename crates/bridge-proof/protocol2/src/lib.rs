mod bitcoin_tx;
mod error;
mod prover;
mod signing_key_proof;
mod statement;
mod tx_inclusion_proof;
mod tx_info;

use bitcoin::{block::Header, consensus::deserialize};
use borsh::{BorshDeserialize, BorshSerialize};
use signing_key_proof::AnchorPublicKeyMerkleProof;
use statement::process_bridge_proof;
use strata_primitives::{buf::Buf32, params::RollupParams, proof::RollupVerifyingKey};
use strata_state::{chain_state::Chainstate, l1::HeaderVerificationState};
use strata_zkvm::ZkVmEnv;
use tx_inclusion_proof::L1TxWithProofBundle;

#[derive(Debug, Clone)]
pub struct BridgeProofInput {
    /// The [RollupParams] of the strata rollup
    rollup_params: RollupParams,

    /// Vector of Bitcoin headers starting after the one that has been verified by the `header_vs`
    headers: Vec<Header>,

    /// The [Chainstate] that can be verified by the strata checkpoint proof.
    chain_state: Chainstate,

    /// The [HeaderVerificationState] used to validate the chain of headers.  
    /// The proof that this HeaderVerificationState is valid must be done extracted from the
    /// `strata_checkpoint_tx`.
    header_vs: HeaderVerificationState,

    /// The index of the deposit within the [Chainstate] deposit table.  
    /// Must match the corresponding information in the withdrawal fulfillment transaction.
    deposit_idx: usize,

    /// Transaction (and its inclusion proof) containing the strata checkpoint proof.  
    /// The `usize` represents the position of this transaction in the header chain.
    strata_checkpoint_tx: (L1TxWithProofBundle, usize),

    /// Transaction (and its inclusion proof) containing the claim.  
    /// The `usize` represents the position of this transaction in the header chain.
    claim_tx: (L1TxWithProofBundle, usize),

    /// Transaction (and its inclusion proof) fulfilling the withdrawal.  
    /// The `usize` represents the position of this transaction in the header chain.
    withdrawal_fulfillment_tx: (L1TxWithProofBundle, usize),

    /// The [AnchorPublicKeyMerkleProof] demonstrating knowledge of the group signing key
    /// for a particular anchor.
    anchor_key_proof: AnchorPublicKeyMerkleProof,

    /// The Merkle root of all group signing keys. Used to verify `anchor_key_proof`.
    anchor_key_root: Buf32,
}

/// Subset of [`BridgeProofInput`] that is [borsh]-serializable
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub(crate) struct BridgeProofInputBorsh {
    chain_state: Chainstate,
    header_vs: HeaderVerificationState,
    deposit_idx: usize,
    strata_checkpoint_tx: (L1TxWithProofBundle, usize),
    claim_tx: (L1TxWithProofBundle, usize),
    withdrawal_fulfillment_tx: (L1TxWithProofBundle, usize),
    anchor_key_proof: AnchorPublicKeyMerkleProof,
    anchor_key_root: Buf32,
}

// Implement `From<&BridgeProofInput>` to create a `BridgeProofInputBorsh`.
impl From<BridgeProofInput> for BridgeProofInputBorsh {
    fn from(input: BridgeProofInput) -> Self {
        Self {
            chain_state: input.chain_state,
            header_vs: input.header_vs,
            deposit_idx: input.deposit_idx,
            strata_checkpoint_tx: input.strata_checkpoint_tx,
            claim_tx: input.claim_tx,
            withdrawal_fulfillment_tx: input.withdrawal_fulfillment_tx,
            anchor_key_proof: input.anchor_key_proof,
            anchor_key_root: input.anchor_key_root,
        }
    }
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BridgeProofOutput {
    anchor_idx: usize,
    anchor_key_root: Buf32,
    deposit_txid: Buf32,
    claim_ts: u32,
    headers_after_claim_tx: usize,
}

pub fn process_bridge_proof_outer(zkvm: &impl ZkVmEnv) {
    let rollup_params: RollupParams = zkvm.read_serde();

    let raw_headers = zkvm.read_buf();
    let headers: Vec<_> = raw_headers
        .chunks_exact(80)
        .map(|chunk| {
            deserialize::<Header>(chunk)
                .expect("Failed to deserialize bitcoin header from 80-byte chunk")
        })
        .collect();

    // TODO: update the strata_primitives?
    let rollup_vk = match rollup_params.rollup_vk() {
        RollupVerifyingKey::SP1VerifyingKey(sp1_vk) => sp1_vk,
        RollupVerifyingKey::Risc0VerifyingKey(risc0_vk) => risc0_vk,
        RollupVerifyingKey::NativeVerifyingKey(native_vk) => native_vk,
    };

    let input: BridgeProofInputBorsh = zkvm.read_borsh();

    let (output, checkpoint) =
        process_bridge_proof(input, headers, rollup_params).expect("expect output");

    // Verify the strata checkpoint proof
    let public_params_raw =
        borsh::to_vec(&checkpoint.get_proof_output()).expect("borsh serialization must not fail");
    zkvm.verify_groth16_proof(checkpoint.proof(), &rollup_vk.0, &public_params_raw);

    zkvm.commit_borsh(&output);
}
