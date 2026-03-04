//! Standard persistence interfaces for a bridge node.

use std::fmt::Debug;

use bitcoin::{OutPoint, Txid};
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::{
    proof::{AsmProof, L1Range, MohoProof},
    types::{DepositIdx, GraphIdx, OperatorIdx},
};
use strata_bridge_sm::{deposit::machine::DepositSM, graph::machine::GraphSM};
use strata_identifiers::L1BlockCommitment;

use crate::types::{FundingPurpose, WriteBatch};

/// Standard persistence interface for a bridge node.
pub trait BridgeDb {
    /// The error type returned by the database operations.
    type Error: Debug;

    /// Gets, if present, a Schnorr [`Signature`] from the database, given an [`OperatorIdx`], a
    /// [`Txid`] and an `input_index`.
    fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> impl Future<Output = Result<Option<Signature>, Self::Error>> + Send;

    /// Sets a Schnorr [`Signature`] from the database, given an [`OperatorIdx`], a [`Txid`] and an
    /// `input_index`.
    fn set_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    // ── Deposit States ───────────────────────────────────────────────

    /// Gets, if present, the [`DepositSM`] for the given [`DepositIdx`].
    fn get_deposit_state(
        &self,
        deposit_idx: DepositIdx,
    ) -> impl Future<Output = Result<Option<DepositSM>, Self::Error>> + Send;

    /// Sets the [`DepositSM`] for the given [`DepositIdx`].
    fn set_deposit_state(
        &self,
        deposit_idx: DepositIdx,
        state: DepositSM,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns all stored deposit states as `(DepositIdx, DepositSM)` pairs.
    fn get_all_deposit_states(
        &self,
    ) -> impl Future<Output = Result<Vec<(DepositIdx, DepositSM)>, Self::Error>> + Send;

    /// Deletes the [`DepositSM`] for the given [`DepositIdx`].
    fn delete_deposit_state(
        &self,
        deposit_idx: DepositIdx,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    // ── Graph States ─────────────────────────────────────────────────

    /// Gets, if present, the serialized graph state for the given
    /// `(DepositIdx, OperatorIdx)` pair.
    fn get_graph_state(
        &self,
        graph_idx: GraphIdx,
    ) -> impl Future<Output = Result<Option<GraphSM>, Self::Error>> + Send;

    /// Sets the serialized graph state for the given `GraphIdx`.
    fn set_graph_state(
        &self,
        graph_idx: GraphIdx,
        state: GraphSM,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns all stored graph states as `(GraphIdx, GraphSM)` triples.
    fn get_all_graph_states(
        &self,
    ) -> impl Future<Output = Result<Vec<(GraphIdx, GraphSM)>, Self::Error>> + Send;

    /// Deletes the serialized graph state for the given `GraphIdx`.
    fn delete_graph_state(
        &self,
        graph_idx: GraphIdx,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    // ── Funds ─────────────────────────────────────────────────────────

    /// Gets, if present, the reserved [`OutPoint`]s for the given graph and purpose.
    fn get_funds(
        &self,
        graph_idx: GraphIdx,
        purpose: FundingPurpose,
    ) -> impl Future<Output = Result<Option<Vec<OutPoint>>, Self::Error>> + Send;

    /// Sets the reserved [`OutPoint`]s for the given graph and purpose.
    fn set_funds(
        &self,
        graph_idx: GraphIdx,
        purpose: FundingPurpose,
        outpoints: Vec<OutPoint>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns all stored funds entries as funding outpoints.
    fn get_all_funds(&self) -> impl Future<Output = Result<Vec<OutPoint>, Self::Error>> + Send;

    /// Deletes the reserved [`OutPoint`]s for the given graph and purpose.
    fn delete_funds(
        &self,
        graph_idx: GraphIdx,
        purpose: FundingPurpose,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    // ── Batch Persistence ─────────────────────────────────────────────

    /// Atomically persists a [`WriteBatch`] of causally-linked state machines
    /// in a single database transaction. On conflict, the implementation
    /// retries with back-off.
    fn persist_batch(
        &self,
        batch: &WriteBatch,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    // ── Cascade Deletes ─────────────────────────────────────────────

    /// Atomically deletes the deposit state and all associated graph states for
    /// the given [`DepositIdx`] in a single transaction.
    fn delete_deposit(
        &self,
        deposit_idx: DepositIdx,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Atomically deletes all graph states associated with the given
    /// [`OperatorIdx`] across all deposits.
    fn delete_operator(
        &self,
        operator_idx: OperatorIdx,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

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

    /// Prunes all proofs (both ASM and Moho) for blocks before the given commitment.
    ///
    /// Deletes all entries with height strictly less than `before`'s height.
    fn prune(
        &self,
        before: L1BlockCommitment,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
}
