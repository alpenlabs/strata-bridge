mod signing_key_proof;
mod tx_inclusion_proof;

use bitcoin::block::Header;
use signing_key_proof::AnchorPublicKeyMerkleProof;
use strata_state::chain_state::Chainstate;
use tx_inclusion_proof::L1TxWithProofBundle;

pub struct BridgeProofInput {
    /// Chain of bitcoin headers
    ///
    /// The first header is the block till where the strata checkpoint verifies the
    /// headerverification state
    /// i.e. if the strata checkpoint verifies till bitcoin block 100. the first header is the
    /// header of the block 101
    headers: Vec<Header>,
    /// Chainstate that can be verified by the strata checkpoint proof
    chain_state: Chainstate,
    deposit_idx: usize,
    /// inclusion proof of the transaction that contains the strata checkpoint proof.
    /// the second usize represents where the transaction is placed in the header chain.
    strata_checkpoint_tx: (L1TxWithProofBundle, usize),
    claim_tx: (L1TxWithProofBundle, usize),
    anchor_proof: AnchorPublicKeyMerkleProof,
}
