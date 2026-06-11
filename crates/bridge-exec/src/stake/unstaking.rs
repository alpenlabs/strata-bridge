//! This module covers executors related to unstaking.
//!
//! This includes broadcasting of the Unstaking Intent transaction as well as the Unstaking
//! transaction itself.

use bitcoin::{OutPoint, Transaction, secp256k1::schnorr};
use btc_tracker::event::TxStatus;
use strata_bridge_connectors::prelude::UnstakingIntentWitness;
use strata_bridge_tx_graph::transactions::{prelude::UnstakingIntentTx, unstaking::UnstakingTx};
use tracing::info;

use crate::{
    chain::{self, CpfpKind, publish_signed_transaction},
    errors::ExecutorError,
    output_handles::OutputHandles,
    stake::utils::get_preimage,
};

pub(crate) async fn publish_unstaking_intent(
    output_handles: &OutputHandles,
    stake_funds: OutPoint,
    unstaking_intent_tx: UnstakingIntentTx,
    n_of_n_signature: &schnorr::Signature,
) -> Result<(), ExecutorError> {
    info!(%stake_funds, "fetching unstaking preimage from secret-service");
    let preimage = get_preimage(&output_handles.s2_client, stake_funds).await?;

    let unstaking_intent_witness = UnstakingIntentWitness {
        n_of_n_signature: *n_of_n_signature,
        unstaking_preimage: preimage,
    };

    let signed_unstaking_intent_tx = unstaking_intent_tx.finalize(&unstaking_intent_witness);
    let unstaking_intent_txid = signed_unstaking_intent_tx.compute_txid();
    info!(%unstaking_intent_txid, "publishing unstaking intent transaction");
    // Unstaking intent carries a keyed anchor; CPFP via InferAnchor.
    publish_signed_transaction(
        output_handles,
        &signed_unstaking_intent_tx,
        "unstaking intent tx",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(&signed_unstaking_intent_tx),
        CpfpKind::InferAnchor,
    )
    .await?;
    info!(%unstaking_intent_txid, "unstaking intent transaction confirmed on-chain");
    Ok(())
}

pub(crate) async fn publish_unstaking_tx(
    output_handles: &OutputHandles,
    signed_tx: &Transaction,
) -> Result<(), ExecutorError> {
    let unstaking_txid = signed_tx.compute_txid();
    info!(%unstaking_txid, "publishing unstaking transaction");
    // Unstaking pays the operator at vout 0 (the operator-controlled output). Use
    // ParentTxCombined — the unstaking tx has no keyed anchor.
    let payout_outpoint = OutPoint {
        txid: signed_tx.compute_txid(),
        vout: UnstakingTx::OPERATOR_VOUT,
    };
    publish_signed_transaction(
        output_handles,
        signed_tx,
        "unstaking tx",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(signed_tx),
        CpfpKind::PayoutCombined { payout_outpoint },
    )
    .await?;
    info!(%unstaking_txid, "unstaking transaction confirmed on-chain");
    Ok(())
}
