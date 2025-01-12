use bitcoin::{block::Header, hashes::Hash, Transaction};
use strata_primitives::{
    buf::Buf32,
    hash::sha256d,
    l1::{TxIdComputable, TxIdMarker, WtxIdMarker},
};
use strata_proofimpl_btc_blockspace::block::witness_commitment_from_coinbase;
use strata_state::l1::{L1TxInclusionProof, L1TxProof, L1WtxProof};

/// A transaction along with its [L1TxInclusionProof], parameterized by a `Marker` type
/// (either [`TxIdMarker`] or [`WtxIdMarker`]).
///
/// This struct pairs the actual Bitcoin [`Transaction`] with its corresponding proof that
/// its `txid` or `wtxid` is included in a given Merkle root. The proof data is carried
/// by the [`L1TxInclusionProof`].
pub struct L1TxWithIdProof<T> {
    /// The transaction in question.
    tx: Transaction,
    /// The Merkle inclusion proof associated with the transaction’s [`Txid`](bitcoin::Txid) or
    /// [`Wtxid`](bitcoin::Wtxid).
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

/// A bundle that holds:
///
/// - a “base” transaction ([`L1TxWithIdProof<TxIdMarker>`]) and
/// - an optional “witness” transaction ([`L1TxWithIdProof<WtxIdMarker>`]).
///
/// This structure is meant to unify the concept of:
/// 1. **Proving a transaction without witness data:** we only need a [`txid`] Merkle proof.
/// 2. **Proving a transaction with witness data:** we provide a [`wtxid`] Merkle proof, plus a
///    coinbase transaction (the “base” transaction) that commits to the witness Merkle root.
pub struct L1TxWithProofBundle {
    /// If `witness_tx` is `None`, this is the actual transaction we want to prove.
    /// If `witness_tx` is `Some`, this becomes the coinbase transaction that commits
    /// to the witness transaction’s `wtxid` in its witness Merkle root.
    base_tx: L1TxWithIdProof<TxIdMarker>,

    /// The witness-inclusive transaction (with its `wtxid` Merkle proof),
    /// present only if the transaction contains witness data.
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
    /// Generates a new [`L1TxWithProofBundle`] from a slice of transactions (`txs`) and an
    /// index (`idx`) pointing to the transaction of interest.
    ///
    /// This function checks whether the target transaction has witness data. If it does not,
    /// a proof is built for its `txid` alone. Otherwise, a proof is built for its `wtxid`,
    /// and the coinbase transaction is used as the “base” transaction with a `txid` proof.
    ///
    /// # Panics
    /// Panics if `idx` is out of bounds for the `txs` array (e.g., `idx as usize >= txs.len()`).
    pub fn generate(txs: &[Transaction], idx: u32) -> Self {
        // Clone the transaction we want to prove.
        let tx = txs[idx as usize].clone();

        // Detect if the transaction has empty witness data for all inputs.
        let witness_empty = tx.input.iter().all(|input| input.witness.is_empty());
        if witness_empty {
            // Build a txid-based proof.
            let tx_proof = L1TxProof::generate(txs, idx);
            let base_tx = L1TxWithIdProof::new(tx, tx_proof);
            Self {
                base_tx,
                witness_tx: None,
            }
        } else {
            // Build a wtxid-based proof for the actual transaction.
            let tx_proof = L1WtxProof::generate(txs, idx);
            let witness_tx = Some(L1TxWithIdProof::new(tx, tx_proof));

            // Use the coinbase transaction (index 0) as the “base” transaction.
            let coinbase = txs[0].clone();
            let coinbase_proof = L1TxProof::generate(txs, 0);
            let base_tx = L1TxWithIdProof::new(coinbase, coinbase_proof);

            Self {
                base_tx,
                witness_tx,
            }
        }
    }

    /// Verifies this [`L1TxWithProofBundle`] against a given [`Header`].
    ///
    /// - If `witness_tx` is `None`, this simply verifies that the `base_tx`’s `txid` is included in
    ///   `header.merkle_root`.
    /// - If `witness_tx` is `Some`, this checks that the coinbase transaction (the “base_tx”) is
    ///   correctly included in `header.merkle_root`, and that the coinbase commits to the witness
    ///   transaction’s `wtxid` in its witness Merkle root.
    pub fn verify(&self, header: Header) -> bool {
        // First, verify that the `base_tx` is in the Merkle tree given by `header.merkle_root`.
        let merkle_root: Buf32 = header.merkle_root.to_byte_array().into();
        if !self.base_tx.verify(merkle_root) {
            return false;
        }

        match &self.witness_tx {
            Some(witness) => {
                let coinbase = &self.base_tx.tx;
                // The base transaction must indeed be a coinbase if we are committing
                // to witness data.
                if !coinbase.is_coinbase() {
                    return false;
                }

                // Compute the witness Merkle root for the transaction in question.
                let L1TxWithIdProof { tx, proof } = witness;
                let mut witness_root = proof.compute_root(tx).as_bytes().to_vec();

                // The coinbase input’s witness must have exactly one element of length 32,
                // which should be the “wtxid” commitment.
                let witness_vec: Vec<_> = coinbase.input[0].witness.iter().collect();
                if witness_vec.len() != 1 || witness_vec[0].len() != 32 {
                    return false;
                }

                // Append the committed data to the `witness_root` bytes.
                witness_root.extend(witness_vec[0]);

                // Double SHA-256 of the root + data gives us the final commitment.
                let commitment = sha256d(&witness_root);

                // Check if the coinbase transaction’s witness commitment matches.
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
