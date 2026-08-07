use bitcoin::{OutPoint, Transaction};
use btc_tracker::event::TxStatus;
use musig2::secp256k1::schnorr::Signature;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_connectors::ParentTx;
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_sm::graph::duties::MultiAnchorSpend;
use strata_bridge_tx_graph::transactions::{
    contested_payout::ContestedPayoutTx, counterproof_ack::CounterproofAckTx, prelude::ContestTx,
};
use tracing::{info, warn};

use crate::{
    chain::{self, CpfpKind, publish_signed_transaction},
    cpfp_adapters::multi_anchor_spend_material,
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

    // Resolve the CPFP data before finalization. The contest tx carries a `MultiAnchor`,
    // and the child spends the leaf keyed to this operator's watchtower slot — the same
    // slot that signed the contest input. A key-path anchor kind cannot describe a
    // script-path spend, so the caller supplies the leaf and control block here.
    let cpfp =
        match multi_anchor_spend_material(contest_tx.cpfp_connector(), watchtower_index as usize) {
            Some((leaf_script, control_block)) => CpfpKind::MultiAnchor {
                anchor_vout: contest_tx.cpfp_outpoint().vout,
                leaf_script,
                control_block,
            },
            None => {
                warn!(
                    watchtower_index,
                    "no MultiAnchor leaf for this operator; publishing contest without CPFP"
                );
                CpfpKind::None
            }
        };

    let signed_tx = contest_tx.finalize(*n_of_n_signature, watchtower_index, watchtower_signature);

    publish_signed_transaction(
        output_handles,
        &signed_tx,
        "contest",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(&signed_tx),
        cpfp,
    )
    .await
}

/// Publishes the bridge proof timeout transaction to the Bitcoin network.
pub(super) async fn publish_bridge_proof_timeout(
    output_handles: &OutputHandles,
    signed_timeout_tx: &Transaction,
    cpfp_anchor: Option<&MultiAnchorSpend>,
) -> Result<(), ExecutorError> {
    // The timeout carries a `MultiAnchor`, so bumping it is a script-path spend of the leaf
    // keyed to our watchtower slot. The state machine resolves that slot — it depends on which
    // operator owns the graph, which the transaction bytes don't reveal. `None` means we own the
    // graph and hold no leaf, so there is nothing to bump with.
    let cpfp = match cpfp_anchor {
        Some(anchor) => CpfpKind::MultiAnchor {
            anchor_vout: anchor.anchor_vout,
            leaf_script: anchor.leaf_script.clone(),
            control_block: anchor.control_block.clone(),
        },
        None => {
            info!("publishing bridge proof timeout for own graph; no watchtower leaf to CPFP with");
            CpfpKind::None
        }
    };

    publish_signed_transaction(
        output_handles,
        signed_timeout_tx,
        "bridge proof timeout",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(signed_timeout_tx),
        cpfp,
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
    // The counterproof-ack carries a keyed anchor at `CounterproofAckTx::CPFP_VOUT`. The
    // anchor key is the watchtower pubkey, which equals the musig2 pubkey (see the
    // watchtower-key note in `bin/strata-bridge::operator_wallet`; the compile-time
    // `_covenant_keys_field_audit` in `crates/common::params` guards the identity). This
    // anchor is not at the dust floor: `CounterproofAckTx` folds the residual of its input
    // connectors into it (2 × dust). The publish-time check therefore accepts each value
    // at or above dust.
    publish_signed_transaction(
        output_handles,
        signed_counter_proof_ack_tx,
        "counterproof ack",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(signed_counter_proof_ack_tx),
        CpfpKind::AnchorAt {
            anchor_vout: CounterproofAckTx::CPFP_VOUT,
        },
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
