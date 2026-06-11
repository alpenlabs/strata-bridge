//! Standard persistence interfaces for a bridge node.

use std::fmt::Debug;

use bitcoin::{OutPoint, Txid};
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::types::{DepositIdx, GraphIdx, OperatorIdx};
use strata_bridge_sm::{
    deposit::machine::DepositSM, graph::machine::GraphSM, stake::machine::StakeSM,
};

use crate::types::{FundingAssignment, StakeFundingReservation, WriteBatch};

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

    // ── Stake States ─────────────────────────────────────────────────

    /// Gets, if present, the [`StakeSM`] for the given [`OperatorIdx`].
    fn get_stake_state(
        &self,
        operator_idx: OperatorIdx,
    ) -> impl Future<Output = Result<Option<StakeSM>, Self::Error>> + Send;

    /// Sets the [`StakeSM`] for the given [`OperatorIdx`].
    fn set_stake_state(
        &self,
        operator_idx: OperatorIdx,
        state: StakeSM,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Returns all stored stake states as `(OperatorIdx, StakeSM)` pairs.
    fn get_all_stake_states(
        &self,
    ) -> impl Future<Output = Result<Vec<(OperatorIdx, StakeSM)>, Self::Error>> + Send;

    /// Deletes the [`StakeSM`] for the given [`OperatorIdx`].
    fn delete_stake_state(
        &self,
        operator_idx: OperatorIdx,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    // ── Funds ─────────────────────────────────────────────────────────

    /// Gets, if present, the reserved [`OutPoint`] used to fund the claim transaction (and
    /// subsequently the entire graph).
    fn get_claim_funding_outpoint(
        &self,
        graph_idx: GraphIdx,
    ) -> impl Future<Output = Result<Option<OutPoint>, Self::Error>> + Send;

    /// Returns the existing claim-funding [`OutPoint`] for `graph_idx`, or stores and returns
    /// `outpoint` when no assignment exists.
    fn get_or_set_claim_funding_outpoint(
        &self,
        graph_idx: GraphIdx,
        outpoint: OutPoint,
    ) -> impl Future<Output = Result<FundingAssignment<OutPoint>, Self::Error>> + Send;

    /// Gets, if present, the [`StakeFundingReservation`] persisted for the given operator.
    fn get_stake_funding_reservation(
        &self,
        operator_idx: OperatorIdx,
    ) -> impl Future<Output = Result<Option<StakeFundingReservation>, Self::Error>> + Send;

    /// Returns the existing stake-funding reservation for `operator_idx`, or stores and returns
    /// `reservation` when no assignment exists.
    fn get_or_set_stake_funding_reservation(
        &self,
        operator_idx: OperatorIdx,
        reservation: StakeFundingReservation,
    ) -> impl Future<Output = Result<FundingAssignment<StakeFundingReservation>, Self::Error>> + Send;

    /// Deletes the [`StakeFundingReservation`] for the given operator.
    fn delete_stake_funding_reservation(
        &self,
        operator_idx: OperatorIdx,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Gets, if present, the reserved [`OutPoint`]s for fulfilling withdrawals requests.
    fn get_withdrawal_funding_outpoints(
        &self,
        deposit_idx: DepositIdx,
    ) -> impl Future<Output = Result<Option<Vec<OutPoint>>, Self::Error>> + Send;

    /// Returns the existing withdrawal-funding [`OutPoint`]s for `deposit_idx`, or stores and
    /// returns `outpoints` when no assignment exists.
    fn get_or_set_withdrawal_funding_outpoints(
        &self,
        deposit_idx: DepositIdx,
        outpoints: Vec<OutPoint>,
    ) -> impl Future<Output = Result<FundingAssignment<Vec<OutPoint>>, Self::Error>> + Send;

    /// Returns all reserved general-wallet outpoints across the claim, stake, and withdrawal rows.
    ///
    /// For stake reservations this is the set of inputs to the funding transaction, not the
    /// resulting reserved-wallet output.
    fn get_all_funds(&self) -> impl Future<Output = Result<Vec<OutPoint>, Self::Error>> + Send;

    /// Deletes the reserved [`OutPoint`]s for the given graph and purpose.
    fn delete_claim_funding_outpoint(
        &self,
        graph_idx: GraphIdx,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    /// Deletes the reserved [`OutPoint`]s for the given graph and purpose.
    fn delete_withdrawal_funding_outpoints(
        &self,
        graph_idx: GraphIdx,
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
