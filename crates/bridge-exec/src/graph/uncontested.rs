//! Executors for payout graph duties.

use bitcoin::{OutPoint, Transaction};
use btc_tracker::event::TxStatus;
use strata_bridge_tx_graph::transactions::uncontested_payout::UncontestedPayoutTx;

use crate::{
    chain::{self, CpfpKind, publish_signed_transaction},
    errors::ExecutorError,
    output_handles::OutputHandles,
};

/// Publishes the signed uncontested payout transaction to Bitcoin.
pub(super) async fn publish_uncontested_payout(
    output_handles: &OutputHandles,
    signed_uncontested_payout_tx: &Transaction,
) -> Result<(), ExecutorError> {
    // Uncontested payout: vout 0 is the operator's payout. No keyed anchor on this tx; use
    // ParentTxCombined so the CPFP child spends that output for fee-bumping.
    let payout_outpoint = OutPoint {
        txid: signed_uncontested_payout_tx.compute_txid(),
        vout: UncontestedPayoutTx::CPFP_VOUT,
    };
    publish_signed_transaction(
        output_handles,
        signed_uncontested_payout_tx,
        "uncontested payout",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(signed_uncontested_payout_tx),
        CpfpKind::PayoutCombined { payout_outpoint },
    )
    .await
}
