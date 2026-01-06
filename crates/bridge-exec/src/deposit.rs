//! This module contains the executors for performing duties related to deposits.

use std::sync::Arc;

use strata_bridge_sm::deposit::duties::DepositDuty;

use crate::{config::ExecutionConfig, output_handles::OutputHandles};

/// Executes the given deposit duty.
pub async fn execute_deposit_duty(
    _cfg: Arc<ExecutionConfig>,
    _output_handles: Arc<OutputHandles>,
    duty: &DepositDuty,
) {
    match duty {
        DepositDuty::PublishDepositNonce { .. } => publish_deposit_nonce().await,
        DepositDuty::PublishDepositPartial { .. } => publish_deposit_partial().await,
        DepositDuty::PublishDeposit { .. } => publish_deposit().await,
        DepositDuty::FulfillWithdrawal => fulfill_withdrawal().await,
        DepositDuty::RequestPayoutNonces => request_payout_nonces().await,
        DepositDuty::PublishPayoutNonce => publish_payout_nonce().await,
        DepositDuty::RequestPayoutPartials => request_payout_partials().await,
        DepositDuty::PublishPayoutPartial => publish_payout_partial().await,
        DepositDuty::PublishPayout => publish_payout().await,
    }
}

async fn publish_deposit_nonce() {
    todo!("@MdTeach")
}

async fn publish_deposit_partial() {
    todo!("@MdTeach")
}

async fn publish_deposit() {
    todo!("@mukeshdroid")
}

async fn fulfill_withdrawal() {
    todo!("@mukeshdroid")
}

async fn request_payout_nonces() {
    todo!("@mukeshdroid")
}

async fn publish_payout_nonce() {
    todo!("@mukeshdroid")
}

async fn request_payout_partials() {
    todo!("@mukeshdroid")
}

async fn publish_payout_partial() {
    todo!("@mukeshdroid")
}

async fn publish_payout() {
    todo!("@Rajil1213")
}
