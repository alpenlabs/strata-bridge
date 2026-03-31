//! Duties related to staking.
//!
//! This covers all duties related to the collection of unstaking signatures upto the publication of
//! the stake transaction.

use bitcoin::Transaction;
use musig2::AggNonce;
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_tx_graph::stake_graph::{StakeData, StakeGraph};

use crate::{config::ExecutionConfig, errors::ExecutorError, output_handles::OutputHandles};

pub(crate) async fn publish_stake_data(
    _cfg: &ExecutionConfig,
    _output_handles: &OutputHandles,
    _operator_idx: OperatorIdx,
) -> Result<(), ExecutorError> {
    // Create stake funding transaction
    // Query a new preimage/hash from s2
    // Get the general wallet descriptor from the wallet/s2.
    todo!("Package and submit to p2p after STR-2643")
}

pub(crate) async fn publish_unstaking_nonces(
    _cfg: &ExecutionConfig,
    _output_handles: &OutputHandles,
    _stake_data: &StakeData,
) -> Result<(), ExecutorError> {
    // generate nonces for each transaction input in the stake transaction graph via s2.
    todo!("Submit to p2p after STR-2643")
}

pub(crate) async fn publish_unstaking_partials(
    _cfg: &ExecutionConfig,
    _output_handles: &OutputHandles,
    _stake_data: &StakeData,
    _agg_nonces: &[AggNonce; StakeGraph::N_MUSIG_INPUTS],
) -> Result<(), ExecutorError> {
    // Generate partial signatures for each transaction input in the stake transaction graph via
    // s2.
    todo!("Submit to p2p after STR-2643")
}

pub(crate) async fn publish_stake(
    _cfg: &ExecutionConfig,
    _output_handles: &OutputHandles,
    _tx: &Transaction,
) -> Result<(), ExecutorError> {
    todo!()
}
