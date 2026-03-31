//! This module covers executors related to unstaking.
//!
//! This includes broadcasting of the Unstaking Intent transaction as well as the Unstaking
//! transaction itself.

use bitcoin::{OutPoint, Transaction, secp256k1::schnorr};
use btc_tracker::event::TxStatus;
use strata_bridge_connectors::prelude::UnstakingIntentWitness;
use strata_bridge_tx_graph::transactions::prelude::UnstakingIntentTx;

use crate::{
    chain::publish_signed_transaction, errors::ExecutorError, output_handles::OutputHandles,
    stake::utils::get_preimage,
};

pub(crate) async fn publish_unstaking_intent(
    output_handles: &OutputHandles,
    stake_funds: OutPoint,
    unstaking_intent_tx: UnstakingIntentTx,
    n_of_n_signature: &schnorr::Signature,
) -> Result<(), ExecutorError> {
    let preimage = get_preimage(&output_handles.s2_client, stake_funds).await?;

    let unstaking_intent_witness = UnstakingIntentWitness {
        n_of_n_signature: *n_of_n_signature,
        unstaking_preimage: preimage,
    };

    let signed_unstaking_intent_tx = unstaking_intent_tx.finalize(&unstaking_intent_witness);

    publish_signed_transaction(
        &output_handles.tx_driver,
        &signed_unstaking_intent_tx,
        "unstaking intent tx",
        TxStatus::is_buried,
    )
    .await
}

pub(crate) async fn publish_unstaking_tx(
    output_handles: &OutputHandles,
    signed_tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_signed_transaction(
        &output_handles.tx_driver,
        signed_tx,
        "unstaking tx",
        TxStatus::is_buried,
    )
    .await
}
