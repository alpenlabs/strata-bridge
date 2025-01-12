use bitcoin::{block::Header, hashes::Hash, Transaction};
use strata_primitives::{
    buf::Buf32,
    hash::sha256d,
    l1::{TxIdComputable, TxIdMarker, WtxIdMarker},
};
use strata_proofimpl_btc_blockspace::block::witness_commitment_from_coinbase;
use strata_state::l1::{L1TxInclusionProof, L1TxProof, L1WtxProof};

/// A transaction along with its L1TxInclusionProof,
/// parameterized by a `Marker` (such as `TxIdMarker` or `WtxIdMarker`).
pub struct L1TxWithIdProof<T> {
    /// The transaction in question.
    tx: Transaction,
    /// The inclusion proof associated with the transaction’s `TxId` or `WtxId`.
    proof: L1TxInclusionProof<T>,
}

impl<T: TxIdComputable> L1TxWithIdProof<T> {
    pub fn new(tx: Transaction, proof: L1TxInclusionProof<T>) -> Self {
        Self { tx, proof }
    }

    pub fn verify(&self, root: Buf32) -> bool {
        self.proof.verify(&self.tx, root)
    }
}

/// Represents a transaction (with optional witness data) and the corresponding proofs
/// that link it all the way up to a block header.
///
/// # Overview
///
/// This structure supports two scenarios:
///
/// - **No witness data (`witness_tx` is `None`)**:   The `base_tx` field is the actual transaction
///   to be proven. The proof shows how this transaction’s `txid` is included in the block’s Merkle
///   tree.
///
/// - **With witness data (`witness_tx` is `Some`)**:   The `witness_tx` field contains the actual
///   transaction (with witness data). Meanwhile, the `base_tx` field holds the coinbase transaction
///   that commits to the `wtxid` in its witness Merkle root. The proof then shows the coinbase
///   transaction’s inclusion in the block, effectively linking the witness-inclusive transaction
///   (`wtxid`) to the block header.
pub struct L1TxWithProofBundle {
    /// If `witness_tx` is `None`, this is the transaction we want to prove.
    /// If `witness_tx` is `Some`, this becomes the coinbase transaction that commits
    /// to the `wtxid` in the witness Merkle root.
    base_tx: L1TxWithIdProof<TxIdMarker>,

    /// The witness-inclusive transaction (and its `wtxid` Merkle proof).
    /// Present only if the transaction contains witness data.
    witness_tx: Option<L1TxWithIdProof<WtxIdMarker>>,
}

impl L1TxWithProofBundle {
    pub fn get_base_tx(&self) -> &L1TxWithIdProof<TxIdMarker> {
        &self.base_tx
    }

    pub fn get_witness_tx(&self) -> &Option<L1TxWithIdProof<WtxIdMarker>> {
        &self.witness_tx
    }
}

impl L1TxWithProofBundle {
    pub fn generate(txs: &[Transaction], idx: u32) -> Self {
        let tx = txs[idx as usize].clone();

        let witness_empty = tx.input.iter().all(|input| input.witness.is_empty());
        if witness_empty {
            let tx_proof = L1TxProof::generate(txs, idx);
            let base_tx = L1TxWithIdProof::new(tx, tx_proof);
            Self {
                base_tx,
                witness_tx: None,
            }
        } else {
            let tx_proof = L1WtxProof::generate(txs, idx);
            let witness_tx = Some(L1TxWithIdProof::new(tx, tx_proof));

            let coinbase = txs[0].clone();
            let coinbase_proof = L1TxProof::generate(txs, 0);
            let base_tx = L1TxWithIdProof::new(coinbase, coinbase_proof);

            Self {
                base_tx,
                witness_tx,
            }
        }
    }

    pub fn verify(&self, header: Header) -> bool {
        let merkle_root: Buf32 = header.merkle_root.to_byte_array().into();
        if !self.base_tx.verify(merkle_root) {
            return false;
        }

        match &self.witness_tx {
            Some(witness) => {
                let coinbase = &self.base_tx.tx;
                if !coinbase.is_coinbase() {
                    return false;
                }
                let L1TxWithIdProof { tx, proof } = witness;

                let mut witness_root = proof.compute_root(tx).as_bytes().to_vec();

                // Gather the witness data; it must have exactly one element of length 32 bytes.
                let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
                if witness_vec.len() != 1 || witness_vec[0].len() != 32 {
                    return false;
                }

                witness_root.extend(witness_vec[0]);

                let commitment = sha256d(&witness_root);

                match witness_commitment_from_coinbase(coinbase) {
                    Some(root) => commitment == root.to_byte_array().into(),
                    None => false,
                }
            }
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use strata_test_utils::bitcoin::get_btc_mainnet_block;

    use super::L1TxWithProofBundle;

    #[test]
    fn test_segwit_tx() {
        let block = get_btc_mainnet_block();
        // This idx doesn't have any witness
        let idx = 4;
        let tx_bundle = L1TxWithProofBundle::generate(&block.txdata, idx);
        assert!(tx_bundle.get_witness_tx().is_none());
        assert!(tx_bundle.verify(block.header));
    }

    #[test]
    fn test_nonsegwit_tx() {
        let block = get_btc_mainnet_block();
        // Most of the other transaction in this block has some witness in the transaction
        let idx = 10;
        let tx_bundle = L1TxWithProofBundle::generate(&block.txdata, idx);
        assert!(tx_bundle.get_witness_tx().is_some());
        assert!(tx_bundle.verify(block.header));
    }
}
