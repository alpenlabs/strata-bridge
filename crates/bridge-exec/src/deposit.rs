//! This module contains the executors for performing duties related to deposits.

use std::{collections::BTreeMap, sync::Arc};

use bitcoin::{
    Amount, FeeRate, OutPoint, TapSighashType, Transaction,
    secp256k1::{Message, PublicKey, XOnlyPublicKey, schnorr},
    sighash::{Prevouts, SighashCache},
};
use bitcoin_bosd::Descriptor;
use bitcoind_async_client::traits::Reader;
use btc_tracker::event::TxStatus;
use musig2::{AggNonce, PartialSignature, PubNonce, aggregate_partial_signatures};
use secret_service_proto::v2::traits::{Musig2Params, Musig2Signer, SchnorrSigner, SecretService};
use strata_bridge_connectors2::SigningInfo;
use strata_bridge_p2p_types2::PayoutDescriptor;
use strata_bridge_primitives::{
    key_agg::create_agg_ctx,
    scripts::taproot::{TaprootTweak, TaprootWitness, create_message_hash},
    types::{BitcoinBlockHeight, DepositIdx, OperatorIdx},
};
use strata_bridge_sm::deposit::duties::DepositDuty;
use strata_bridge_tx_graph2::transactions::prelude::{
    CooperativePayoutTx, WithdrawalFulfillmentData, WithdrawalFulfillmentTx,
};
use tracing::{error, info, warn};

use crate::{config::ExecutionConfig, errors::ExecutorError, output_handles::OutputHandles};

/// Executes the given deposit duty.
pub async fn execute_deposit_duty(
    cfg: Arc<ExecutionConfig>,
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
        DepositDuty::FulfillWithdrawal {
            deposit_idx,
            deadline,
            recipient_desc,
            deposit_amount,
        } => {
            fulfill_withdrawal(
                &cfg,
                &output_handles,
                *deposit_idx,
                *deadline,
                recipient_desc.clone(),
                *deposit_amount,
            )
            .await
        }
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

/// Fulfills a withdrawal request by fronting funds to the user.
///
/// Only the assignee executes this duty.
async fn fulfill_withdrawal(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    deposit_idx: DepositIdx,
    deadline: BitcoinBlockHeight,
    recipient_desc: Descriptor,
    deposit_amount: Amount,
) -> Result<(), ExecutorError> {
    info!(%deposit_idx, %deadline, dest=%recipient_desc, "executing fulfill_withdrawal duty");

    // Check if we're within the fulfillment window
    let fulfillment_window = cfg.min_withdrawal_fulfillment_window;
    let cur_height = output_handles
        .bitcoind_rpc_client
        .get_blockchain_info()
        .await?
        .blocks;

    let reached_deadline = (cur_height as u64) >= deadline.saturating_sub(fulfillment_window);
    if reached_deadline {
        warn!(
            %cur_height,
            %deadline,
            %fulfillment_window,
            "current height exceeds deadline minus fulfillment window, skipping"
        );
        return Ok(());
    }

    // Calculate the amount to send to user (deposit_amount - operator_fee)
    let amount = deposit_amount
        .checked_sub(cfg.operator_fee)
        .expect("deposit amount must be greater than operator fee");

    // Get fee rate estimate from bitcoind
    let fee_rate = output_handles
        .bitcoind_rpc_client
        .estimate_smart_fee(1)
        .await
        .map_err(|e| ExecutorError::WalletErr(format!("failed to estimate fee: {e}")))?;
    let fee_rate = FeeRate::from_sat_per_vb(fee_rate).unwrap_or(FeeRate::DUST);

    // Check if fee rate exceeds maximum configured rate
    if fee_rate > cfg.maximum_fee_rate {
        warn!(
            %fee_rate,
            maximum_fee_rate = %cfg.maximum_fee_rate,
            "fee rate exceeds maximum, skipping fulfillment"
        );
        return Ok(());
    }

    // Create unfunded WithdrawalFulfillmentTx with outputs only
    let wft_data = WithdrawalFulfillmentData {
        deposit_idx,
        user_amount: amount,
        magic_bytes: cfg.magic_bytes,
    };
    let wft = WithdrawalFulfillmentTx::new(wft_data, recipient_desc);
    let unfunded_tx = wft.into_unsigned_tx();

    // Fund the transaction via wallet (adds inputs and change)
    let wft_psbt = {
        let mut wallet = output_handles.wallet.write().await;

        info!("syncing wallet before funding withdrawal fulfillment tx");
        if let Err(e) = wallet.sync().await {
            warn!(?e, "could not sync wallet, continuing anyway");
        }

        match wallet.fund_v3_transaction(unfunded_tx, fee_rate) {
            Ok(psbt) => psbt,
            Err(err) => {
                error!(%err, "could not fund withdrawal");
                return Ok(());
            }
        }
    };

    // Sign each input
    let txid = wft_psbt.unsigned_tx.compute_txid();
    info!(%txid, "signing withdrawal fulfillment transaction");

    let mut sighash_cache = SighashCache::new(&wft_psbt.unsigned_tx);

    let prevouts: Vec<_> = wft_psbt
        .inputs
        .iter()
        .filter_map(|input| input.witness_utxo.clone())
        .collect();
    let prevouts = Prevouts::All(&prevouts);

    let mut signed_tx = wft_psbt.unsigned_tx.clone();
    for (input_index, _) in wft_psbt.inputs.iter().enumerate() {
        let msg = create_message_hash(
            &mut sighash_cache,
            prevouts.clone(),
            &TaprootWitness::Key,
            TapSighashType::Default,
            input_index,
        )
        .map_err(|e| ExecutorError::WalletErr(format!("sighash error: {e}")))?;

        let signature = output_handles
            .s2_client
            .general_wallet_signer()
            .sign(msg.as_ref(), None)
            .await?;

        signed_tx.input[input_index]
            .witness
            .push(signature.serialize());
    }

    // Broadcast and wait for confirmation
    info!(%txid, "submitting withdrawal fulfillment tx to the tx driver");
    output_handles
        .tx_driver
        .drive(signed_tx, TxStatus::is_buried)
        .await?;

    info!(%txid, %deposit_idx, "withdrawal fulfillment confirmed");
    Ok(())
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
