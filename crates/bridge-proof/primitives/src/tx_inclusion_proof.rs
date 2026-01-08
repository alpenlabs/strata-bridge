//! Transaction inclusion proof.

use std::marker::PhantomData;

use bitcoin::{block::Header, hashes::Hash, Transaction};
use borsh::{BorshDeserialize, BorshSerialize};
use strata_crypto::hash::sha256d;
use strata_primitives::buf::Buf32;

use crate::{tx::BitcoinTx, utils::witness_commitment_from_coinbase};

/// A generic proof structure that can handle any kind of transaction ID (e.g.,
/// [`Txid`](bitcoin::Txid) or [`Wtxid`](bitcoin::Wtxid)) by delegating the ID computation to the
/// provided type `T` that implements [`TxIdComputable`].
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct L1TxInclusionProof<T> {
    /// The 0-based position (index) of the transaction within the block's transaction list
    /// for which this proof is generated.
    position: u32,

    /// The intermediate hashes (sometimes called "siblings") needed to reconstruct the Merkle root
    /// when combined with the target transaction's own ID. These are the Merkle tree nodes at
    /// each step that pair with the current hash (either on the left or the right) to produce
    /// the next level of the tree.
    cohashes: Vec<Buf32>,

    /// A marker that preserves the association with type `T`, which implements
    /// [`TxIdComputable`]. This ensures the proof logic depends on the correct
    /// transaction ID computation ([`Txid`](bitcoin::Txid) vs.[`Wtxid`](bitcoin::Wtxid)) for the
    /// lifetime of the proof.
    _marker: PhantomData<T>,
}

impl<T> L1TxInclusionProof<T> {
    /// Creates a new transaction inclusion proof.
    pub const fn new(position: u32, cohashes: Vec<Buf32>) -> Self {
        Self {
            position,
            cohashes,
            _marker: PhantomData,
        }
    }

    /// Returns a reference to the cohashes (Merkle tree sibling hashes) in this proof.
    ///
    /// These are the intermediate hashes needed to reconstruct the Merkle root
    /// when combined with the target transaction's ID.
    pub fn cohashes(&self) -> &[Buf32] {
        &self.cohashes
    }

    /// Returns the 0-based position of the transaction within the block.
    pub const fn position(&self) -> u32 {
        self.position
    }
}

/// A trait for computing some kind of transaction ID (e.g., [`Txid`](bitcoin::Txid) or
/// [`Wtxid`](bitcoin::Wtxid)) from a [`Transaction`].
///
/// This trait is designed to be implemented by "marker" types that define how a transaction ID
/// should be computed. For example, [`TxIdMarker`] invokes [`Transaction::compute_txid`], and
/// [`WtxIdMarker`] invokes [`Transaction::compute_wtxid`]. This approach avoids duplicating
/// inclusion-proof or serialization logic across multiple ID computations.
pub trait TxIdComputable {
    /// Computes the transaction ID for the given transaction.
    ///
    /// The `idx` parameter allows marker types to handle special cases such as the coinbase
    /// transaction (which has a zero [`Wtxid`](bitcoin::Wtxid)) by looking up the transaction
    /// index.
    fn compute_id(tx: &Transaction, idx: usize) -> Buf32;
}

/// Marker type for computing the [`Txid`](bitcoin::Txid).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct TxIdMarker;

/// Marker type for computing the [`Wtxid`](bitcoin::Wtxid).
#[derive(Clone, Debug, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct WtxIdMarker;

impl TxIdComputable for TxIdMarker {
    fn compute_id(tx: &Transaction, _idx: usize) -> Buf32 {
        tx.compute_txid().into()
    }
}

impl TxIdComputable for WtxIdMarker {
    fn compute_id(tx: &Transaction, idx: usize) -> Buf32 {
        // Coinbase transaction wtxid is hash with zeroes
        if idx == 0 {
            return Buf32::zero();
        }
        tx.compute_wtxid().into()
    }
}

impl<T: TxIdComputable> L1TxInclusionProof<T> {
    /// Generates the proof for a transaction at the specified index in the list of
    /// transactions, using `T` to compute the transaction IDs.
    pub fn generate(transactions: &[Transaction], idx: u32) -> Self {
        let txids = transactions
            .iter()
            .enumerate()
            .map(|(idx, tx)| T::compute_id(tx, idx))
            .collect::<Vec<_>>();
        let (cohashes, _txroot) = get_cohashes(&txids, idx);
        L1TxInclusionProof::new(idx, cohashes)
    }

    /// Computes the merkle root for the given `transaction` using the proof's cohashes.
    pub fn compute_root(&self, transaction: &Transaction) -> Buf32 {
        // `cur_hash` represents the intermediate hash at each step. After all cohashes are
        // processed `cur_hash` becomes the root hash
        let mut cur_hash = T::compute_id(transaction, self.position as usize).0;

        let mut pos = self.position();
        for cohash in self.cohashes() {
            let mut buf = [0u8; 64];
            if pos & 1 == 0 {
                buf[0..32].copy_from_slice(&cur_hash);
                buf[32..64].copy_from_slice(cohash.as_ref());
            } else {
                buf[0..32].copy_from_slice(cohash.as_ref());
                buf[32..64].copy_from_slice(&cur_hash);
            }
            cur_hash = sha256d(&buf).0;
            pos >>= 1;
        }
        Buf32::from(cur_hash)
    }

    /// Verifies the inclusion proof of the given `transaction` against the provided merkle `root`.
    pub fn verify(&self, transaction: &Transaction, root: Buf32) -> bool {
        self.compute_root(transaction) == root
    }
}

/// Computes the Merkle cohashes needed for a transaction inclusion proof.
///
/// Given a list of transaction IDs and an index, this function computes the
/// Merkle tree hashes needed to prove that the transaction at `index` is
/// included in the tree.
///
/// Returns a tuple of (cohashes, root) where:
/// - cohashes: The sibling hashes needed for the proof path
/// - root: The Merkle root of the tree
pub fn get_cohashes<T>(ids: &[T], index: u32) -> (Vec<Buf32>, Buf32)
where
    T: Into<Buf32> + Clone,
{
    assert!(
        (index as usize) < ids.len(),
        "The transaction index should be within the txids length"
    );
    let mut curr_level: Vec<Buf32> = ids.iter().cloned().map(Into::into).collect();

    let mut curr_index = index;
    let mut cohashes = vec![];
    while curr_level.len() > 1 {
        let mut next_level = vec![];
        let mut i = 0;
        while i < curr_level.len() {
            let left = curr_level[i];
            let right = if i + 1 < curr_level.len() {
                curr_level[i + 1]
            } else {
                curr_level[i] // duplicate last element if odd
            };

            // Store the cohash (sibling of our path)
            if i == curr_index as usize {
                cohashes.push(right);
            } else if i + 1 == curr_index as usize {
                cohashes.push(left);
            }

            // Compute parent hash
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(left.as_ref());
            combined[32..].copy_from_slice(right.as_ref());
            let parent = sha256d(&combined);
            next_level.push(parent);

            i += 2;
        }

        curr_index /= 2;
        curr_level = next_level;
    }

    let root = curr_level[0];
    (cohashes, root)
}

/// Convenience type alias for the [`Txid`](bitcoin::Txid)-based proof.
pub type L1TxProof = L1TxInclusionProof<TxIdMarker>;

/// Convenience type alias for the [`Wtxid`](bitcoin::Wtxid)-based proof.
pub type L1WtxProof = L1TxInclusionProof<WtxIdMarker>;

/// A transaction along with its [L1TxInclusionProof], parameterized by a `Marker` type
/// (either [`TxIdMarker`] or [`WtxIdMarker`]).
///
/// This struct pairs the actual Bitcoin [`Transaction`] with its corresponding proof that
/// its `txid` or `wtxid` is included in a given Merkle root. The proof data is carried
/// by the [`L1TxInclusionProof`].
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct L1TxWithIdProof<T> {
    /// The transaction in question.
    tx: BitcoinTx,
    /// The Merkle inclusion proof associated with the transaction’s [`Txid`](bitcoin::Txid) or
    /// [`Wtxid`](bitcoin::Wtxid).
    proof: L1TxInclusionProof<T>,
}

impl<T: TxIdComputable> L1TxWithIdProof<T> {
    // Ignored for now. This is meant to be called from elsewhere to generate to the format to be
    // used by the prover
    pub(crate) const fn new(tx: BitcoinTx, proof: L1TxInclusionProof<T>) -> Self {
        Self { tx, proof }
    }

    pub(crate) fn verify(&self, root: Buf32) -> bool {
        self.proof.verify(self.tx.as_ref(), root)
    }
}

/// A bundle that holds:
///
/// - a “base” transaction ([`L1TxWithIdProof<TxIdMarker>`]) and
/// - an optional “witness” transaction ([`L1TxWithIdProof<WtxIdMarker>`]).
///
/// This structure is meant to unify the concept of:
/// 1. **Proving a transaction without witness data:** we only need a [`Txid`](bitcoin::Txid) Merkle
///    proof.
/// 2. **Proving a transaction with witness data:** we provide a [`Wtxid`](bitcoin::Wtxid) Merkle
///    proof, plus a coinbase transaction (the “base” transaction) that commits to the witness
///    Merkle root.
#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
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
    /// Returns the transaction for which this bundle includes a proof.
    /// If the transaction does not have any witness data, this returns `None`.
    pub const fn get_witness_tx(&self) -> &Option<L1TxWithIdProof<WtxIdMarker>> {
        &self.witness_tx
    }

    /// Returns the actual transaction included in this bundle.
    /// If witness data is available, it returns the transaction from `witness_tx`,
    /// otherwise, it falls back to the base transaction.
    pub fn transaction(&self) -> &Transaction {
        match &self.witness_tx {
            Some(tx) => tx.tx.as_ref(),
            None => self.base_tx.tx.as_ref(),
        }
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
    // Ignored for now. This is meant to be called from elsewhere to generate to the format to be
    // used by the prover
    pub fn generate(txs: &[Transaction], idx: u32) -> Self {
        // Clone the transaction we want to prove.
        let tx = txs[idx as usize].clone();

        // Detect if the transaction has empty witness data for all inputs.
        let witness_empty = tx.input.iter().all(|input| input.witness.is_empty());
        if witness_empty {
            // Build a txid-based proof.
            let tx_proof = L1TxProof::generate(txs, idx);
            let base_tx = L1TxWithIdProof::new(tx.into(), tx_proof);
            Self {
                base_tx,
                witness_tx: None,
            }
        } else {
            // Build a wtxid-based proof for the actual transaction.
            let tx_proof = L1WtxProof::generate(txs, idx);
            let witness_tx = Some(L1TxWithIdProof::new(tx.into(), tx_proof));

            // Use the coinbase transaction (index 0) as the “base” transaction.
            let coinbase = txs[0].clone();
            let coinbase_proof = L1TxProof::generate(txs, 0);
            let base_tx = L1TxWithIdProof::new(coinbase.into(), coinbase_proof);

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
                let coinbase = self.base_tx.tx.as_ref();
                // The base transaction must indeed be a coinbase if we are committing
                // to witness data.
                if !coinbase.is_coinbase() {
                    return false;
                }

                // Compute the witness Merkle root for the transaction in question.
                let L1TxWithIdProof { tx, proof } = witness;
                let mut witness_root = proof.compute_root(tx.as_ref()).as_bytes().to_vec();

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
    use bitcoin::Block;
    use strata_primitives::Buf32;

    use super::*;

    #[test]
    fn test_get_cohashes_from_wtxids_idx_2() {
        let input = vec![
            Buf32::from([1; 32]),
            Buf32::from([2; 32]),
            Buf32::from([3; 32]),
            Buf32::from([4; 32]),
            Buf32::from([5; 32]),
        ];

        let (cohashes, _root) = get_cohashes(&input, 2);
        assert_eq!(cohashes.len(), 3);
    }

    #[test]
    fn test_get_cohashes_from_wtxids_idx_5() {
        let input = vec![
            Buf32::from([1; 32]),
            Buf32::from([2; 32]),
            Buf32::from([3; 32]),
            Buf32::from([4; 32]),
            Buf32::from([5; 32]),
            Buf32::from([6; 32]),
        ];

        let (cohashes, _root) = get_cohashes(&input, 5);
        assert_eq!(cohashes.len(), 3);
    }

    #[test]
    fn test_segwit_tx() {
        let blocks_bytes = std::fs::read("../../../test-data/blocks.bin").unwrap();
        let blocks: Vec<Block> = bincode::deserialize(&blocks_bytes).unwrap();

        // Select a block with more than one transaction and construct the proof for the last
        // transaction in the block
        let block = blocks.iter().find(|block| block.txdata.len() > 1).unwrap();
        let idx = block.txdata.len() - 1;

        let tx_bundle = L1TxWithProofBundle::generate(&block.txdata, idx as u32);
        assert!(tx_bundle.get_witness_tx().is_some());
        assert!(tx_bundle.verify(block.header));
    }
}
