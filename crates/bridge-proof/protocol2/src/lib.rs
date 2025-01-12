mod error;
mod signing_key_proof;
mod statement;
mod bitcoin_tx;
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

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct BridgeProofInput {
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

    // TODO: update the primitives
    let rollup_vk = match rollup_params.rollup_vk() {
        RollupVerifyingKey::SP1VerifyingKey(sp1_vk) => sp1_vk,
        RollupVerifyingKey::Risc0VerifyingKey(risc0_vk) => risc0_vk,
        RollupVerifyingKey::NativeVerifyingKey(native_vk) => native_vk,
    };

    let input: BridgeProofInput = zkvm.read_borsh();

    let output = process_bridge_proof(input, headers, rollup_params);

    zkvm.commit_borsh(&output);
}
