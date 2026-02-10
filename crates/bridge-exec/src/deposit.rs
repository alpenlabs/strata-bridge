//! This module contains the executors for performing duties related to deposits.

use std::sync::Arc;

use bitcoin::{
    OutPoint, Transaction,
    secp256k1::{Message, XOnlyPublicKey},
};
use btc_tracker::event::TxStatus;
use musig2::{AggNonce, PartialSignature, PubNonce};
use secret_service_proto::v2::traits::{Musig2Params, Musig2Signer, SecretService};
use strata_bridge_primitives::{scripts::taproot::TaprootWitness, types::DepositIdx};
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
        } => {
            publish_deposit_nonce(
                &output_handles,
                *deposit_idx,
                *drt_outpoint,
                ordered_pubkeys,
            )
            .await
        }
        DepositDuty::PublishDepositPartial {
            deposit_idx,
            drt_outpoint,
            deposit_sighash,
            deposit_agg_nonce,
            ordered_pubkeys,
        } => {
            publish_deposit_partial(
                &output_handles,
                *deposit_idx,
                *drt_outpoint,
                *deposit_sighash,
                deposit_agg_nonce.clone(),
                ordered_pubkeys,
            )
            .await
        }
        DepositDuty::PublishDeposit {
            signed_deposit_transaction,
        } => publish_deposit(&output_handles, signed_deposit_transaction.clone()).await,
        DepositDuty::FulfillWithdrawal { .. } => fulfill_withdrawal().await,
        DepositDuty::RequestPayoutNonces { .. } => request_payout_nonces().await,
        DepositDuty::PublishPayoutNonce { .. } => publish_payout_nonce().await,
        DepositDuty::PublishPayoutPartial { .. } => publish_payout_partial().await,
        DepositDuty::PublishPayout { .. } => publish_payout().await,
    }
}

/// Publishes the operator's nonce for the deposit transaction signing session.
///
/// This is the first step in the MuSig2 signing flow for deposit transactions.
/// Each operator generates and broadcasts their public nonce, which will be
/// aggregated before partial signatures can be generated.
async fn publish_deposit_nonce(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    drt_outpoint: OutPoint,
    ordered_pubkeys: &[XOnlyPublicKey],
) -> Result<(), ExecutorError> {
    info!(%drt_outpoint, "executing publish_deposit_nonce duty");

    // Create Musig2Params for key-path spend (n-of-n)
    let params = Musig2Params {
        ordered_pubkeys: ordered_pubkeys.to_vec(),
        witness: TaprootWitness::Key,
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

/// Publishes the operator's partial signature for the deposit transaction signing session.
///
/// This is the second step in the MuSig2 signing flow for deposit transactions.
/// Each operator generates a partial signature using their secret nonce (derived from
/// the same params used in nonce generation) and the aggregated nonce from all operators.
async fn publish_deposit_partial(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    drt_outpoint: OutPoint,
    deposit_sighash: Message,
    deposit_agg_nonce: AggNonce,
    ordered_pubkeys: &[XOnlyPublicKey],
) -> Result<(), ExecutorError> {
    info!(%drt_outpoint, "executing publish_deposit_partial duty");

    // Create Musig2Params for key-path spend (n-of-n)
    // Must use same params as nonce generation for deterministic nonce recovery
    let params = Musig2Params {
        ordered_pubkeys: ordered_pubkeys.to_vec(),
        witness: TaprootWitness::Key,
        input: drt_outpoint,
    };

    // Generate partial signature via secret service
    let partial_sig: PartialSignature = output_handles
        .s2_client
        .musig2_signer()
        .get_our_partial_sig(params, deposit_agg_nonce, *deposit_sighash.as_ref())
        .await?
        .map_err(|e| match e.to_enum() {
            terrors::E2::A(_) => ExecutorError::OurPubKeyNotInParams,
            terrors::E2::B(_) => ExecutorError::SelfVerifyFailed,
        })?;

    // Broadcast via MessageHandler2
    output_handles
        .msg_handler2
        .write()
        .await
        .send_deposit_partial(deposit_idx, partial_sig, None)
        .await;

    info!(%drt_outpoint, %deposit_idx, "published deposit partial");
    Ok(())
}

/// Publishes the deposit transaction to the Bitcoin network.
async fn publish_deposit(
    output_handles: &OutputHandles,
    signed_deposit_transaction: Transaction,
) -> Result<(), ExecutorError> {
    let txid = signed_deposit_transaction.compute_txid();
    info!(%txid, "executing publish_deposit duty");

    // Broadcast and wait for burial confirmation
    // Note: The transaction is already finalized by the state machine
    output_handles
        .tx_driver
        .drive(signed_deposit_transaction, TxStatus::is_buried)
        .await?;

    info!(%txid, "deposit transaction confirmed");
    Ok(())
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
