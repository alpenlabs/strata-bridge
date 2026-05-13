//! Duties related to staking.
//!
//! This covers all duties related to the collection of unstaking signatures upto the publication of
//! the stake transaction.

use bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, Psbt, TapSighashType, Transaction, TxOut,
    hashes::{Hash, sha256},
    key::TapTweak,
    secp256k1::{Message, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache},
};
use bitcoin_bosd::Descriptor;
use bitcoind_async_client::traits::Reader;
use btc_tracker::event::TxStatus;
use futures::{FutureExt, future::try_join_all};
use musig2::{AggNonce, PubNonce};
use secret_service_proto::v2::traits::{Musig2Params, Musig2Signer, SchnorrSigner, SecretService};
use strata_bridge_connectors::prelude::UnstakingIntentOutput;
use strata_bridge_db::{traits::BridgeDb, types::StakeFundingReservation};
use strata_bridge_p2p_types::UnstakingInput;
use strata_bridge_primitives::{
    scripts::taproot::{TaprootTweak, create_key_spend_hash},
    types::OperatorIdx,
};
use strata_bridge_tx_graph::{fee, musig_functor::StakeFunctor, transactions::prelude::StakeTx};
use tracing::{error, info, warn};

use crate::{
    chain::publish_signed_transaction, config::ExecutionConfig, errors::ExecutorError,
    output_handles::OutputHandles, stake::utils::get_preimage,
};

pub(crate) async fn publish_stake_data(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    operator_idx: OperatorIdx,
) -> Result<(), ExecutorError> {
    info!(%operator_idx, "checking for a persisted stake funding reservation");
    let reservation = match output_handles
        .db
        .get_stake_funding_reservation(operator_idx)
        .await?
    {
        Some(reservation) => {
            info!(%operator_idx, "reusing persisted stake funding reservation");
            reservation
        }
        None => {
            info!(%operator_idx, "no persisted stake funding reservation; creating a new funding tx");
            create_and_persist_stake_funding(cfg, output_handles, operator_idx).await?
        }
    };

    let stake_funds = OutPoint {
        txid: reservation.unsigned_tx.compute_txid(),
        vout: reservation.stake_output_vout,
    };

    info!(%operator_idx, %stake_funds, "submitting stake funding transaction");
    let signed_tx = sign_reservation(output_handles, &reservation).await?;
    publish_signed_transaction(
        &output_handles.tx_driver,
        &signed_tx,
        "stake funding tx",
        TxStatus::is_buried,
    )
    .await?;

    info!("fetching unstaking intent preimage from secret-service");
    let preimage = get_preimage(&output_handles.s2_client, stake_funds).await?;
    let unstaking_image = sha256::Hash::hash(&preimage);
    info!(%unstaking_image, "fetched unstaking intent preimage and computed the unstaking image");

    info!("constructing the unstaking output descriptor");
    let general_wallet_key = output_handles
        .s2_client
        .general_wallet_signer()
        .pubkey()
        .await?;
    // Safety: the general wallet uses the operator's pubkey directly as the taproot output key
    // (no additional tweak), so the pubkey returned by secret-service is already tweaked.
    let address = Address::p2tr_tweaked(general_wallet_key.dangerous_assume_tweaked(), cfg.network);
    info!(%address, "constructed the unstaking output address");

    let output_desc = Descriptor::try_from(address)
        .expect("must be able to create descriptor from a valid address");

    let unstaking_input = UnstakingInput {
        stake_funds,
        unstaking_image,
        unstaking_operator_desc: output_desc.into(),
    };

    info!(%operator_idx, "broadcasting the unstaking input to the p2p network");
    let mut msg_handler = output_handles.msg_handler.write().await;
    msg_handler
        .send_unstaking_input(operator_idx, unstaking_input, None)
        .await;

    Ok(())
}

async fn create_and_persist_stake_funding(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    operator_idx: OperatorIdx,
) -> Result<StakeFundingReservation, ExecutorError> {
    info!("fetching fee rate from bitcoind");
    let fee_rate = output_handles
        .bitcoind_rpc_client
        .estimate_smart_fee(1)
        .await?;
    info!(%fee_rate, "fetched fee rate from bitcoind");

    // Bound the rate from below by `fee::FEE_RATE` so this v3 (TRUC) funding transaction
    // always meets the bridge's hardcoded minimum, even on networks like signet where
    // `estimatesmartfee` may return a value below `minrelaytxfee`.
    let fee_rate = FeeRate::from_sat_per_vb(fee_rate)
        .unwrap_or(fee::FEE_RATE)
        .max(fee::FEE_RATE);

    if fee_rate > cfg.maximum_fee_rate {
        return Err(ExecutorError::FeeRateTooHigh {
            fee_rate,
            max: cfg.maximum_fee_rate,
        });
    }

    let funding_amount = stake_funding_amount(cfg.network, cfg.stake_amount);

    info!(%fee_rate, %funding_amount, "creating stake funding transaction");
    let psbt = {
        let mut wallet = output_handles.wallet.write().await;

        match wallet.sync().await {
            Ok(()) => info!("synced wallet successfully"),
            Err(e) => error!(
                ?e,
                "could not sync wallet before creating stake funding tx; still attempting"
            ),
        }

        wallet
            .create_stake_funding_tx(fee_rate, funding_amount)
            .expect("must be able to create stake funding transaction")
    };

    let reservation = reservation_from_psbt(&psbt);

    info!(%operator_idx, "persisting stake funding reservation");
    output_handles
        .db
        .set_stake_funding_reservation(operator_idx, reservation.clone())
        .await?;

    Ok(reservation)
}

fn reservation_from_psbt(psbt: &Psbt) -> StakeFundingReservation {
    let prevouts = psbt
        .inputs
        .iter()
        .map(|input| {
            input
                .witness_utxo
                .as_ref()
                .expect("stake funding PSBT input must have a witness utxo")
                .clone()
        })
        .collect();
    // The stake funding PSBT is built with `TxOrdering::Untouched` and a single recipient at
    // index 0; change (if any) is appended after.
    StakeFundingReservation {
        unsigned_tx: psbt.unsigned_tx.clone(),
        prevouts,
        stake_output_vout: 0,
    }
}

async fn sign_reservation(
    output_handles: &OutputHandles,
    reservation: &StakeFundingReservation,
) -> Result<Transaction, ExecutorError> {
    let prevouts = Prevouts::All(&reservation.prevouts);

    const DEFAULT_SIGHASH_TYPE: TapSighashType = TapSighashType::Default;

    let mut sighash_cache = SighashCache::new(&reservation.unsigned_tx);
    let sighashes = (0..reservation.unsigned_tx.input.len()).map(|input_index| {
        create_key_spend_hash(
            &mut sighash_cache,
            prevouts.clone(),
            DEFAULT_SIGHASH_TYPE,
            input_index,
        )
        .expect("must be able to create key spend hash")
    });

    let s2_signer = output_handles.s2_client.general_wallet_signer();
    let mut signatures = Vec::with_capacity(reservation.unsigned_tx.input.len());
    for sighash in sighashes {
        let signature = s2_signer
            .sign(sighash.as_ref(), None)
            .await
            .map_err(ExecutorError::SecretServiceErr)?;
        signatures.push(signature);
    }

    let mut signed_tx = reservation.unsigned_tx.clone();
    for (input, signature) in signed_tx.input.iter_mut().zip(signatures) {
        input.witness.push(signature.serialize());
    }

    Ok(signed_tx)
}

pub(crate) async fn publish_unstaking_nonces(
    output_handles: &OutputHandles,
    operator_idx: OperatorIdx,
    graph_inpoints: StakeFunctor<OutPoint>,
    graph_tweaks: StakeFunctor<TaprootTweak>,
    ordered_pubkeys: Vec<XOnlyPublicKey>,
) -> Result<(), ExecutorError> {
    info!(%operator_idx, "generating and publishing unstaking nonces for the stake graph");

    let musig_signer = output_handles.s2_client.musig2_signer();

    let nonce_futures = graph_inpoints.zip(graph_tweaks).into_iter()
        .map(|(inpoint, tweak)| {
            let params = Musig2Params {
                ordered_pubkeys: ordered_pubkeys.clone(),
                tweak,
                input: inpoint,
            };

            musig_signer.get_pub_nonce(params).map(move |res| match res {
                Ok(inner) => inner.map_err(|_| {
                    warn!(%operator_idx, %inpoint, "failed to get pub nonce from secret-service: our pubkey missing from params");
                    ExecutorError::OurPubKeyNotInParams
                }),
                Err(e) => {
                    warn!(%operator_idx, %inpoint, ?e, "failed to get pub nonce from secret-service");
                    Err(ExecutorError::SecretServiceErr(e))
                }
            })
        });

    let nonces: Vec<PubNonce> = try_join_all(nonce_futures).await?;

    output_handles
        .msg_handler
        .write()
        .await
        .send_unstaking_nonces(operator_idx, nonces, None)
        .await;
    info!(%operator_idx, "successfully published unstaking nonces for the stake graph");

    Ok(())
}

pub(crate) async fn publish_unstaking_partials(
    output_handles: &OutputHandles,
    operator_idx: OperatorIdx,
    graph_inpoints: StakeFunctor<OutPoint>,
    graph_tweaks: StakeFunctor<TaprootTweak>,
    sighashes: StakeFunctor<Message>,
    agg_nonces: StakeFunctor<AggNonce>,
    ordered_pubkeys: Vec<XOnlyPublicKey>,
) -> Result<(), ExecutorError> {
    info!(%operator_idx, "generating and publishing unstaking partial signatures for the stake graph");

    let musig_signer = output_handles.s2_client.musig2_signer();

    let partial_futures = StakeFunctor::zip4(graph_inpoints, graph_tweaks, sighashes, agg_nonces)
        .map(|(inpoint, tweak, sighash, agg_nonce)| {
            let params = Musig2Params {
                ordered_pubkeys: ordered_pubkeys.clone(),
                tweak,
                input: inpoint,
            };

            musig_signer
                .get_our_partial_sig(params, agg_nonce, *sighash.as_ref())
                .map(move |res| match res {
                    Ok(inner) => inner.map_err(|e| match e.to_enum() {
                        terrors::E2::A(_) => {
                            warn!(?operator_idx, %inpoint, "secret service rejected partial sig request: our pubkey missing from params");
                            ExecutorError::OurPubKeyNotInParams
                        }
                        terrors::E2::B(_) => {
                            warn!(?operator_idx, %inpoint, "secret service rejected partial sig request: self-verification failed");
                            ExecutorError::SelfVerifyFailed
                        }
                    }),
                    Err(e) => {
                        warn!(%operator_idx, %inpoint, ?e, "failed to get partial signature from secret-service");
                        Err(ExecutorError::SecretServiceErr(e))
                    }
                })
        },
    );

    let partials = try_join_all(partial_futures).await?;
    info!(%operator_idx, "successfully generated unstaking partial signatures for the stake graph");

    output_handles
        .msg_handler
        .write()
        .await
        .send_unstaking_partials(operator_idx, partials, None)
        .await;
    info!(%operator_idx, "successfully published unstaking partial signatures for the stake graph");

    Ok(())
}

pub(crate) async fn publish_stake(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    tx: &Transaction,
) -> Result<(), ExecutorError> {
    let stake_txid = tx.compute_txid();
    let funding_input = tx.input[0].previous_output;

    // The stake tx spends a single funding UTXO in the stakechain wallet and is not presigned by
    // the covenant, so key-path sign it with the stakechain wallet signer before broadcasting.
    // Reconstruct the prevout from known values: the funding UTXO is always at the stakechain
    // address with value `stake_amount + unstaking_intent_output.value() + stake_fee`.
    let stakechain_script = {
        let wallet = output_handles.wallet.read().await;
        wallet.stakechain_script_buf().clone()
    };
    let funding_amount = stake_funding_amount(cfg.network, cfg.stake_amount);
    let prevout = TxOut {
        script_pubkey: stakechain_script,
        value: funding_amount,
    };

    info!(
        %stake_txid,
        %funding_input,
        %funding_amount,
        "signing stake transaction with stakechain wallet signer"
    );

    let prevouts = Prevouts::All(&[prevout]);
    let mut sighash_cache = SighashCache::new(tx);
    let sighash = create_key_spend_hash(&mut sighash_cache, prevouts, TapSighashType::Default, 0)
        .expect("must be able to create key spend sighash");

    let signature = output_handles
        .s2_client
        .stakechain_wallet_signer()
        .sign(sighash.as_ref(), None)
        .await
        .map_err(ExecutorError::SecretServiceErr)?;

    let mut signed_tx = tx.clone();
    signed_tx.input[0].witness.push(signature.serialize());

    info!(%stake_txid, "publishing signed stake transaction");
    publish_signed_transaction(
        &output_handles.tx_driver,
        &signed_tx,
        "stake tx",
        TxStatus::is_buried,
    )
    .await?;
    info!(%stake_txid, "stake transaction confirmed on-chain");

    Ok(())
}

/// Returns the wallet UTXO value needed to fund the stake transaction on the given network.
///
/// The stake transaction spends this UTXO into the NOfN stake connector (`stake_amount`), the
/// unstaking-intent connector (with its presigned-tx fee surcharge baked in), a zero-value CPFP
/// anchor, and the stake transaction's own fee.
fn stake_funding_amount(network: Network, stake_amount: Amount) -> Amount {
    // `UnstakingIntentOutput::value()` is the P2TR script's `minimal_non_dust()` plus a surcharge
    // that depends only on the script kind — not on the particular n-of-n key or unstaking image.
    // We supply a dummy x-only pubkey (the generator point's x-coordinate) and a zero image so we
    // can compute the value without a secret-service round trip.
    let dummy_pubkey = XOnlyPublicKey::from_slice(&bitcoin::key::constants::GENERATOR_X)
        .expect("valid x-only key");
    let unstaking_intent_output = UnstakingIntentOutput::new(
        network,
        dummy_pubkey,
        sha256::Hash::all_zeros(),
        fee::unstaking_intent_surcharge(),
    );
    StakeTx::stake_funds_required(stake_amount, &unstaking_intent_output)
}
