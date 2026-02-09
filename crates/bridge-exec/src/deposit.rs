//! This module contains the executors for performing duties related to deposits.

use std::sync::Arc;

use bitcoin::{OutPoint, secp256k1::XOnlyPublicKey};
use musig2::PubNonce;
use secret_service_proto::v2::traits::{Musig2Params, Musig2Signer, SecretService};
use strata_bridge_primitives::{scripts::taproot::TaprootTweak, types::DepositIdx};
use strata_bridge_sm::deposit::duties::DepositDuty;
use tracing::info;

use crate::{config::ExecutionConfig, errors::ExecutorError, output_handles::OutputHandles};

/// Executes the given deposit duty.
pub async fn execute_deposit_duty(
    _cfg: Arc<ExecutionConfig>,
    output_handles: Arc<OutputHandles>,
    duty: &DepositDuty,
) -> Result<(), ExecutorError> {
    match duty {
        DepositDuty::PublishDepositNonce {
            deposit_idx,
            drt_outpoint,
            ordered_pubkeys,
            drt_tweak,
        } => {
            publish_deposit_nonce(
                &output_handles,
                *deposit_idx,
                *drt_outpoint,
                ordered_pubkeys,
                *drt_tweak,
            )
            .await
        }
        DepositDuty::PublishDepositPartial { .. } => publish_deposit_partial().await,
        DepositDuty::PublishDeposit { .. } => publish_deposit().await,
        DepositDuty::FulfillWithdrawal { .. } => fulfill_withdrawal().await,
        DepositDuty::RequestPayoutNonces { .. } => request_payout_nonces().await,
        DepositDuty::PublishPayoutNonce { .. } => publish_payout_nonce().await,
        DepositDuty::PublishPayoutPartial { .. } => publish_payout_partial().await,
        DepositDuty::PublishPayout { .. } => publish_payout().await,
    }
}

/// Publishes the operator's nonce for the deposit transaction signing session.
async fn publish_deposit_nonce(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    drt_outpoint: OutPoint,
    ordered_pubkeys: &[XOnlyPublicKey],
    drt_tweak: TaprootTweak,
) -> Result<(), ExecutorError> {
    info!(%drt_outpoint, "executing publish_deposit_nonce duty");

    // Create Musig2Params for key-path spend (n-of-n)
    // The tweak is the merkle root of the DRT's take-back script
    let params = Musig2Params {
        ordered_pubkeys: ordered_pubkeys.to_vec(),
        tweak: drt_tweak,
        input: drt_outpoint,
    };

    // Generate nonce via secret service
    let nonce: PubNonce = output_handles
        .s2_client
        .musig2_signer()
        .get_pub_nonce(params)
        .await?
        .map_err(|_| ExecutorError::OurPubKeyNotInParams)?;

    // Broadcast via MessageHandler2
    output_handles
        .msg_handler2
        .write()
        .await
        .send_deposit_nonce(deposit_idx, nonce, None)
        .await;

    info!(%drt_outpoint, %deposit_idx, "published deposit nonce");
    Ok(())
}

async fn publish_deposit_partial() -> Result<(), ExecutorError> {
    todo!("@MdTeach")
}

async fn publish_deposit() -> Result<(), ExecutorError> {
    todo!("@mukeshdroid")
}

async fn fulfill_withdrawal() -> Result<(), ExecutorError> {
    todo!("@mukeshdroid")
}

async fn request_payout_nonces() -> Result<(), ExecutorError> {
    todo!("@mukeshdroid")
}

async fn publish_payout_nonce() -> Result<(), ExecutorError> {
    todo!("@mukeshdroid")
}

async fn publish_payout_partial() -> Result<(), ExecutorError> {
    todo!("@mukeshdroid")
}

async fn publish_payout() -> Result<(), ExecutorError> {
    todo!("@Rajil1213")
}
