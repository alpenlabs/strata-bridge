//! This module contains the executors for performing duties related to deposits.

use std::{collections::BTreeMap, sync::Arc};

use bitcoin::{
    OutPoint, Transaction,
    secp256k1::{Message, PublicKey, XOnlyPublicKey, schnorr},
};
use bitcoin_bosd::Descriptor;
use btc_tracker::event::TxStatus;
use musig2::{AggNonce, PartialSignature, PubNonce, aggregate_partial_signatures};
use secret_service_proto::v2::traits::{Musig2Params, Musig2Signer, SchnorrSigner, SecretService};
use strata_bridge_connectors2::SigningInfo;
use strata_bridge_p2p_types2::PayoutDescriptor;
use strata_bridge_primitives::{
    key_agg::create_agg_ctx,
    scripts::taproot::TaprootTweak,
    types::{DepositIdx, OperatorIdx},
};
use strata_bridge_sm::deposit::duties::DepositDuty;
use strata_bridge_tx_graph2::transactions::prelude::CooperativePayoutTx;
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
        DepositDuty::PublishDepositPartial {
            deposit_idx,
            drt_outpoint,
            signing_info,
            deposit_agg_nonce,
            ordered_pubkeys,
        } => {
            publish_deposit_partial(
                &output_handles,
                *deposit_idx,
                *drt_outpoint,
                *signing_info,
                deposit_agg_nonce.clone(),
                ordered_pubkeys,
            )
            .await
        }
        DepositDuty::PublishDeposit {
            signed_deposit_transaction,
        } => publish_deposit(&output_handles, signed_deposit_transaction.clone()).await,
        DepositDuty::FulfillWithdrawal { .. } => fulfill_withdrawal().await,
        DepositDuty::RequestPayoutNonces {
            deposit_idx,
            pov_operator_idx,
        } => request_payout_nonces(&output_handles, *deposit_idx, *pov_operator_idx).await,
        DepositDuty::PublishPayoutNonce {
            deposit_idx,
            deposit_outpoint,
            ordered_pubkeys,
        } => {
            publish_payout_nonce(
                &output_handles,
                *deposit_idx,
                *deposit_outpoint,
                ordered_pubkeys,
            )
            .await
        }
        DepositDuty::PublishPayoutPartial {
            deposit_idx,
            deposit_outpoint,
            payout_sighash,
            agg_nonce,
            ordered_pubkeys,
        } => {
            publish_payout_partial(
                &output_handles,
                *deposit_idx,
                *deposit_outpoint,
                *payout_sighash,
                agg_nonce.clone(),
                ordered_pubkeys,
            )
            .await
        }
        DepositDuty::PublishPayout {
            deposit_outpoint,
            agg_nonce,
            collected_partials,
            payout_coop_tx,
            ordered_pubkeys,
            pov_operator_idx,
        } => {
            publish_payout(
                &output_handles,
                *deposit_outpoint,
                agg_nonce.clone(),
                collected_partials.clone(),
                payout_coop_tx.clone(),
                ordered_pubkeys,
                *pov_operator_idx,
            )
            .await
        }
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

/// Publishes the operator's partial signature for the deposit transaction signing session.
async fn publish_deposit_partial(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    drt_outpoint: OutPoint,
    signing_info: SigningInfo,
    deposit_agg_nonce: AggNonce,
    ordered_pubkeys: &[XOnlyPublicKey],
) -> Result<(), ExecutorError> {
    info!(%drt_outpoint, "executing publish_deposit_partial duty");

    // Create Musig2Params for key-path spend (n-of-n)
    // Must use same params as nonce generation for deterministic nonce recovery
    // The tweak is the merkle root of the DRT's take-back script
    let params = Musig2Params {
        ordered_pubkeys: ordered_pubkeys.to_vec(),
        tweak: signing_info.tweak,
        input: drt_outpoint,
    };

    // Generate partial signature via secret service
    let partial_sig: PartialSignature = output_handles
        .s2_client
        .musig2_signer()
        .get_our_partial_sig(params, deposit_agg_nonce, *signing_info.sighash.as_ref())
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
    let drt_txid = signed_deposit_transaction.input[0].previous_output.txid;
    info!(%txid, %drt_txid, "executing publish_deposit duty");

    // Broadcast and wait for burial confirmation
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

/// Initiates the cooperative payout flow by publishing the assignee's payout descriptor.
///
/// Only the assignee executes this duty. The descriptor tells other operators
/// where the assignee wants to receive their payout funds.
async fn request_payout_nonces(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    operator_idx: OperatorIdx,
) -> Result<(), ExecutorError> {
    info!(%deposit_idx, "executing request_payout_nonces duty");

    // TODO (mukeshdroid): Ideally, the s2 client could provide the descriptor directly instead of
    // simply returning the public key.
    // Get the general wallet public key for the payout descriptor
    let pubkey = output_handles
        .s2_client
        .general_wallet_signer()
        .pubkey()
        .await?;

    // Create a P2TR descriptor for the payout address.
    let descriptor = Descriptor::new_p2tr(&pubkey.serialize())
        .map_err(|e| ExecutorError::WalletErr(format!("failed to create descriptor: {e}")))?;

    // Convert to PayoutDescriptor for P2P transmission
    let payout_descriptor: PayoutDescriptor = descriptor.into();

    // Broadcast to all operators
    output_handles
        .msg_handler2
        .write()
        .await
        .send_payout_descriptor(deposit_idx, operator_idx, payout_descriptor.clone(), None)
        .await;

    info!(%deposit_idx, %operator_idx, ?payout_descriptor, "published payout descriptor");
    Ok(())
}

/// Publishes the operator's nonce for the cooperative payout signing session.
async fn publish_payout_nonce(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    deposit_outpoint: OutPoint,
    ordered_pubkeys: &[XOnlyPublicKey],
) -> Result<(), ExecutorError> {
    info!(%deposit_outpoint, "executing publish_payout_nonce duty");

    // Create Musig2Params for key-path spend (n-of-n)
    let params = Musig2Params {
        ordered_pubkeys: ordered_pubkeys.to_vec(),
        tweak: TaprootTweak::Key { tweak: None },
        input: deposit_outpoint,
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
        .send_payout_nonce(deposit_idx, nonce, None)
        .await;

    info!(%deposit_outpoint, %deposit_idx, "published payout nonce");
    Ok(())
}

/// Publishes the operator's partial signature for the cooperative payout signing session.
///
/// Only non-assignees execute this duty - the assignee never publishes their partial signature;
/// they use it locally when aggregating the final signature to prevent payout-tx hostage attacks.
async fn publish_payout_partial(
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    deposit_outpoint: OutPoint,
    payout_sighash: Message,
    payout_agg_nonce: AggNonce,
    ordered_pubkeys: &[XOnlyPublicKey],
) -> Result<(), ExecutorError> {
    info!(%deposit_outpoint, "executing publish_payout_partial duty");

    // Create Musig2Params for key-path spend (n-of-n)
    // Same params as nonce generation for deterministic nonce recovery
    let params = Musig2Params {
        ordered_pubkeys: ordered_pubkeys.to_vec(),
        tweak: TaprootTweak::Key { tweak: None },
        input: deposit_outpoint,
    };

    // Generate partial signature via secret service
    let partial_sig: PartialSignature = output_handles
        .s2_client
        .musig2_signer()
        .get_our_partial_sig(params, payout_agg_nonce, *payout_sighash.as_ref())
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
        .send_payout_partial(deposit_idx, partial_sig, None)
        .await;

    info!(%deposit_outpoint, %deposit_idx, "published payout partial");
    Ok(())
}

/// Publishes the cooperative payout transaction to the Bitcoin network.
///
/// This is the final step in the cooperative payout flow, executed only by the assignee.
/// The assignee:
/// 1. Generates their own partial signature (withheld until now for security)
/// 2. Aggregates all n partial signatures into the final Schnorr signature
/// 3. Finalizes and broadcasts the transaction
///
/// Security: The assignee never publishes their partial signature; they use it locally
/// when aggregating the final signature.
async fn publish_payout(
    output_handles: &OutputHandles,
    deposit_outpoint: OutPoint,
    payout_agg_nonce: AggNonce,
    collected_partials: BTreeMap<OperatorIdx, PartialSignature>,
    payout_coop_tx: Box<CooperativePayoutTx>,
    ordered_pubkeys: &[XOnlyPublicKey],
    pov_operator_idx: OperatorIdx,
) -> Result<(), ExecutorError> {
    let txid = (*payout_coop_tx).as_ref().compute_txid();
    info!(%txid, "executing publish_payout duty");

    // Derive the sighash from the cooperative payout transaction
    let payout_sighash = payout_coop_tx
        .signing_info()
        .first()
        .expect("cooperative payout transaction must have signing info")
        .sighash;

    // Create Musig2Params for key-path spend (n-of-n)
    // Must use same params as nonce generation for deterministic nonce recovery
    let params = Musig2Params {
        ordered_pubkeys: ordered_pubkeys.to_vec(),
        tweak: TaprootTweak::Key { tweak: None },
        input: deposit_outpoint,
    };

    // Generate assignee's partial signature
    let assignee_partial: PartialSignature = output_handles
        .s2_client
        .musig2_signer()
        .get_our_partial_sig(params, payout_agg_nonce.clone(), *payout_sighash.as_ref())
        .await?
        .map_err(|e| match e.to_enum() {
            terrors::E2::A(_) => ExecutorError::OurPubKeyNotInParams,
            terrors::E2::B(_) => ExecutorError::SelfVerifyFailed,
        })?;

    // Collect all n partial signatures (ours + collected from others)
    // Order them by operator index for deterministic aggregation
    let mut all_partials: BTreeMap<OperatorIdx, PartialSignature> = collected_partials;
    all_partials.insert(pov_operator_idx, assignee_partial);

    // Extract partials in operator index order
    let ordered_partials: Vec<PartialSignature> = all_partials.into_values().collect();

    // Create key aggregation context with taproot tweak
    let btc_keys: Vec<PublicKey> = ordered_pubkeys
        .iter()
        .map(|xonly| xonly.public_key(bitcoin::secp256k1::Parity::Even))
        .collect();
    let key_agg_ctx = create_agg_ctx(btc_keys, &TaprootTweak::Key { tweak: None })
        .map_err(|e| ExecutorError::SignatureAggregationFailed(format!("key agg failed: {e}")))?;

    // Aggregate all partial signatures into final Schnorr signature
    let agg_signature: schnorr::Signature = aggregate_partial_signatures(
        &key_agg_ctx,
        &payout_agg_nonce,
        ordered_partials,
        payout_sighash.as_ref(),
    )
    .map_err(|e| ExecutorError::SignatureAggregationFailed(format!("{e}")))?;

    // Finalize the transaction using CooperativePayoutTx.finalize()
    let finalized_tx = (*payout_coop_tx).finalize(agg_signature);

    // Broadcast and wait for confirmation
    output_handles
        .tx_driver
        .drive(finalized_tx, TxStatus::is_buried)
        .await?;

    info!(%txid, "cooperative payout transaction confirmed");
    Ok(())
}
