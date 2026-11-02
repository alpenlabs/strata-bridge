//! Executors for payout graph duties.

use bitcoin::Transaction;
use btc_tracker::cpfp::DeadlineClass;
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
    // This tx has no keyed anchor, so the child spends the operator's payout.
    publish_signed_transaction(
        output_handles,
        signed_uncontested_payout_tx,
        "uncontested payout",
        CpfpKind::PayoutCombined {
            payout_vout: UncontestedPayoutTx::CPFP_VOUT,
            parent_fee: chain::ParentFee::FromPrevouts,
            deadline: DeadlineClass::NoDeadline,
        },
    )
    .await
}
