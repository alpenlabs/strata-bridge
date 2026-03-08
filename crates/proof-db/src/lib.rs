//! Sled-based proof storage.

use std::fmt::Debug;

use strata_bridge_primitives::proof::{AsmProof, L1Range, MohoProof};
use strata_identifiers::L1BlockCommitment;

mod sled;

pub use self::sled::SledProofDb;

/// Persistence interface for proof storage.
pub trait ProofDb {
    /// The error type returned by the database operations.
    type Error: Debug;

    /// Stores an ASM step proof for the given L1 range.
    fn store_asm_proof(
        &self,
        range: L1Range,
        proof: AsmProof,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves an ASM step proof for the given L1 range, if one exists.
    fn get_asm_proof(
        &self,
        range: L1Range,
    ) -> impl Future<Output = Result<Option<AsmProof>, Self::Error>> + Send;

    /// Stores a Moho recursive proof anchored at the given L1 block commitment.
    fn store_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
        proof: MohoProof,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Retrieves a Moho proof for the given L1 block commitment, if one exists.
    fn get_moho_proof(
        &self,
        l1ref: L1BlockCommitment,
    ) -> impl Future<Output = Result<Option<MohoProof>, Self::Error>> + Send;

    /// Retrieves the latest (highest height) Moho proof and its L1 block commitment.
    ///
    /// Returns `None` if no Moho proofs have been stored yet.
    ///
    /// NOTE: Multiple proofs can exist at the same height (e.g. due to reorgs).
    /// In that case, the returned entry is determined by the underlying key
    /// ordering (height, then blkid bytes), which may be arbitrary. Callers that
    /// need the proof for a specific canonical block should use
    /// [`get_moho_proof`](Self::get_moho_proof) with the exact commitment.
    fn get_latest_moho_proof(
        &self,
    ) -> impl Future<Output = Result<Option<(L1BlockCommitment, MohoProof)>, Self::Error>> + Send;

    /// Prunes all proofs (both ASM and Moho) for blocks before the given height.
    ///
    /// Deletes all entries with height strictly less than `before_height`.
    fn prune(&self, before_height: u32) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
