//! Standard persistence interfaces for a bridge node.

use std::fmt::Debug;

use bitcoin::{OutPoint, Txid};
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx};
use strata_bridge_sm::{deposit::machine::DepositSM, graph::machine::GraphSM};

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
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
    ) -> impl Future<Output = Result<Option<GraphSM>, Self::Error>> + Send;

    /// Sets the serialized graph state for the given `(DepositIdx, OperatorIdx)` pair.
    fn set_graph_state(
        &self,
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
        state: GraphSM,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns all stored graph states as `(DepositIdx, OperatorIdx, bytes)` triples.
    fn get_all_graph_states(
        &self,
    ) -> impl Future<Output = Result<Vec<(GraphIdx, GraphSM)>, Self::Error>> + Send;

    /// Deletes the serialized graph state for the given `(DepositIdx, OperatorIdx)` pair.
    fn delete_graph_state(
        &self,
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    // ── Funds ─────────────────────────────────────────────────────────

    /// Gets, if present, the reserved [`OutPoint`]s for the given deposit, operator, and purpose.
    fn get_funds(
        &self,
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
        purpose: FundingPurpose,
    ) -> impl Future<Output = Result<Option<Vec<OutPoint>>, Self::Error>> + Send;

    /// Sets the reserved [`OutPoint`]s for the given deposit, operator, and purpose.
    fn set_funds(
        &self,
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
        purpose: FundingPurpose,
        outpoints: Vec<OutPoint>,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns all stored funds entries as funding outpoints.
    fn get_all_funds(&self) -> impl Future<Output = Result<Vec<OutPoint>, Self::Error>> + Send;

    /// Deletes the reserved [`OutPoint`]s for the given deposit, operator, and purpose. Idempotent.
    fn delete_funds(
        &self,
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
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
