//! This module covers executors related to unstaking.
//!
//! This includes broadcasting of the Unstaking Intent transaction as well as the Unstaking
//! transaction itself.

use bitcoin::{OutPoint, Transaction, secp256k1::schnorr};
use strata_bridge_tx_graph::transactions::prelude::UnstakingIntentTx;

use crate::{config::ExecutionConfig, errors::ExecutorError, output_handles::OutputHandles};

pub(crate) async fn publish_unstaking_intent(
    _cfg: &ExecutionConfig,
    _output_handles: &OutputHandles,
    _stake_funding_outpoint: OutPoint,
    _unstaking_intent_tx: UnstakingIntentTx,
    _n_of_n_signature: &schnorr::Signature,
) -> Result<(), ExecutorError> {
    todo!()
}

pub(crate) async fn publish_unstaking_tx(
    _cfg: &ExecutionConfig,
    _output_handles: &OutputHandles,
    _signed_tx: &Transaction,
) -> Result<(), ExecutorError> {
    todo!()
}
