use bitcoin::Transaction;
use btc_tracker::event::TxStatus;
use musig2::secp256k1::schnorr::Signature;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_tx_graph::transactions::prelude::ContestTx;
use tracing::{info, warn};

use crate::{
    chain::publish_signed_transaction, errors::ExecutorError, output_handles::OutputHandles,
};

/// Signs and publishes the contest transaction to challenge a faulty claim.
pub(super) async fn publish_contest(
    output_handles: &OutputHandles,
    contest_tx: ContestTx,
    n_of_n_signature: &Signature,
    watchtower_index: OperatorIdx,
) -> Result<(), ExecutorError> {
    info!(
        watchtower_index,
        "signing and publishing contest transaction"
    );

    let signing_info = contest_tx.signing_info(watchtower_index);

    let watchtower_signature = output_handles
        .s2_client
        .musig2_signer()
        .sign_no_tweak(signing_info.sighash.as_ref())
        .await
        .map_err(|e| {
            warn!(watchtower_index, ?e, "failed to sign contest transaction");
            ExecutorError::SecretServiceErr(e)
        })?;

    let signed_tx = contest_tx.finalize(*n_of_n_signature, watchtower_index, watchtower_signature);

    publish_signed_transaction(
        &output_handles.tx_driver,
        &signed_tx,
        "contest",
        TxStatus::is_buried,
    )
    .await
}

/// Publishes the bridge proof timeout transaction to the Bitcoin network.
pub(super) async fn publish_bridge_proof_timeout(
    output_handles: &OutputHandles,
    signed_timeout_tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_signed_transaction(
        &output_handles.tx_driver,
        signed_timeout_tx,
        "bridge proof timeout",
        TxStatus::is_buried,
    )
    .await
}

/// Publishes the signed contested payout transaction to Bitcoin.
pub(super) async fn publish_contested_payout(
    output_handles: &OutputHandles,
    signed_contested_payout_tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_signed_transaction(
        &output_handles.tx_driver,
        signed_contested_payout_tx,
        "contested payout",
        TxStatus::is_buried,
    )
    .await
}

/// Publishes the signed counterproof ACK transaction to Bitcoin.
pub(super) async fn publish_counterproof_ack(
    output_handles: &OutputHandles,
    signed_counter_proof_ack_tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_signed_transaction(
        &output_handles.tx_driver,
        signed_counter_proof_ack_tx,
        "counterproof ack",
        TxStatus::is_buried,
    )
    .await
}

/// Publishes the signed slash transaction to Bitcoin.
pub(super) async fn publish_slash(
    output_handles: &OutputHandles,
    signed_slash_tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_signed_transaction(
        &output_handles.tx_driver,
        signed_slash_tx,
        "slash",
        TxStatus::is_buried,
    )
    .await
}
