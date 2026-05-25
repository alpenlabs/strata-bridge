use bitcoin::{OutPoint, Transaction};
use btc_tracker::event::TxStatus;
use musig2::secp256k1::schnorr::Signature;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_tx_graph::transactions::{
    contested_payout::ContestedPayoutTx, prelude::ContestTx,
};
use tracing::{info, warn};

use crate::{
    chain::{self, CpfpKind, publish_signed_transaction},
    errors::ExecutorError,
    output_handles::OutputHandles,
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
        output_handles,
        &signed_tx,
        "contest",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(&signed_tx),
        CpfpKind::InferAnchor,
    )
    .await
}

/// Publishes the bridge proof timeout transaction to the Bitcoin network.
pub(super) async fn publish_bridge_proof_timeout(
    output_handles: &OutputHandles,
    signed_timeout_tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_signed_transaction(
        output_handles,
        signed_timeout_tx,
        "bridge proof timeout",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(signed_timeout_tx),
        CpfpKind::InferAnchor,
    )
    .await
}

/// Publishes the signed contested payout transaction to Bitcoin.
pub(super) async fn publish_contested_payout(
    output_handles: &OutputHandles,
    signed_contested_payout_tx: &Transaction,
) -> Result<(), ExecutorError> {
    // Contested payout: vout 0 is the contesting operator's payout. Use ParentTxCombined.
    let payout_outpoint = OutPoint {
        txid: signed_contested_payout_tx.compute_txid(),
        vout: ContestedPayoutTx::CPFP_VOUT,
    };
    publish_signed_transaction(
        output_handles,
        signed_contested_payout_tx,
        "contested payout",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(signed_contested_payout_tx),
        CpfpKind::PayoutCombined { payout_outpoint },
    )
    .await
}

/// Publishes the signed counterproof ACK transaction to Bitcoin.
pub(super) async fn publish_counterproof_ack(
    output_handles: &OutputHandles,
    signed_counter_proof_ack_tx: &Transaction,
) -> Result<(), ExecutorError> {
    // The counterproof-ack carries a keyed anchor — historically keyed to the watchtower
    // pubkey (today equal to the musig2 pubkey per
    // `bin/strata-bridge::operator_wallet`'s note that those sets coincide). The
    // `InferAnchor` matcher looks at the musig2 pubkey, so this works as long as that
    // identity holds; if the keys ever diverge, the orchestrator startup-time assertion
    // would catch the regression.
    publish_signed_transaction(
        output_handles,
        signed_counter_proof_ack_tx,
        "counterproof ack",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(signed_counter_proof_ack_tx),
        CpfpKind::InferAnchor,
    )
    .await
}

/// Publishes the signed slash transaction to Bitcoin.
pub(super) async fn publish_slash(
    output_handles: &OutputHandles,
    signed_slash_tx: &Transaction,
) -> Result<(), ExecutorError> {
    // Slash pays each watchtower at `vout = 1 + their_index_in_watchtowers` keyed to their
    // `payout_descriptor`. The bridge's convention is that every operator's payout
    // descriptor resolves to their general-wallet P2TR, so `InferGeneralPayout` finds the
    // calling watchtower's specific payout output by script-match — no need to thread the
    // index through bridge-sm. If no matching output exists (e.g. operator's
    // payout_descriptor diverges from their general-wallet key), the helper falls back to
    // no-CPFP.
    publish_signed_transaction(
        output_handles,
        signed_slash_tx,
        "slash",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(signed_slash_tx),
        CpfpKind::InferGeneralPayout,
    )
    .await
}
