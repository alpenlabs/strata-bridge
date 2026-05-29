//! Duties related to staking.
//!
//! This covers all duties related to the collection of unstaking signatures upto the publication of
//! the stake transaction.

use bitcoin::{
    Amount, FeeRate, Network, OutPoint, Psbt, TapSighashType, Transaction, TxOut,
    hashes::{Hash, sha256},
    secp256k1::{Message, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache},
};
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
    chain::{self, CpfpKind, publish_signed_transaction},
    config::ExecutionConfig,
    errors::ExecutorError,
    output_handles::OutputHandles,
    stake::utils::get_preimage,
};

pub(crate) async fn publish_stake_data(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    operator_idx: OperatorIdx,
) -> Result<(), ExecutorError> {
    info!(%operator_idx, "executing duty to publish stake data");

    let reservation = read_or_create_stake_funding(cfg, output_handles, operator_idx).await?;

    let stake_funding_txid = reservation.unsigned_tx.compute_txid();
    let stake_funds = OutPoint {
        txid: stake_funding_txid,
        vout: reservation.stake_output_vout,
    };

    info!(%operator_idx, %stake_funding_txid, "submitting stake funding transaction");
    let signed_tx = sign_reservation(output_handles, &reservation).await?;
    // The funding tx is wallet-funded; its exact fee is the sum of input prevouts (from the
    // reservation) minus the sum of outputs. CPFP needs the exact value because the child's
    // fee math depends on it (see `chain::publish_signed_transaction` docs).
    let stake_funding_fee = chain::exact_fee_from_prevouts(&reservation.prevouts, &signed_tx)
        .ok_or_else(|| {
            ExecutorError::WalletErr("stake funding fee arithmetic overflowed".into())
        })?;
    // Stake funding is wallet-funded. The reserved-wallet output at vout 0 is consumed
    // immediately by the stake tx (can't CPFP via it without conflicting), but BDK
    // typically adds a change output to the general wallet. `InferGeneralPayout` finds
    // that change output and uses it as the CPFP payout; if no change exists (inputs
    // exactly match), the helper falls back to no-CPFP.
    publish_signed_transaction(
        output_handles,
        &signed_tx,
        "stake funding tx",
        TxStatus::is_buried,
        stake_funding_fee,
        CpfpKind::InferGeneralPayout,
    )
    .await?;

    info!("fetching unstaking intent preimage from secret-service");
    let preimage = get_preimage(&output_handles.s2_client, stake_funds).await?;
    let unstaking_image = sha256::Hash::hash(&preimage);
    info!(%unstaking_image, "fetched unstaking intent preimage and computed the unstaking image");

    info!("constructing the unstaking output descriptor");
    // Backend-aware receive destination: where this operator gets its unstaking funds (native
    // general-key P2TR vs Fireblocks vault P2WPKH), so the funds land somewhere it can spend.
    // For the native backend this is byte-identical to the previous P2TR-over-general-key
    // descriptor.
    let output_desc = output_handles.wallet.read().await.payout_descriptor();

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

async fn read_or_create_stake_funding(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    operator_idx: OperatorIdx,
) -> Result<StakeFundingReservation, ExecutorError> {
    let funding_amount = stake_funding_amount(cfg.network, cfg.stake_amount);

    let mut wallet = output_handles.wallet.write().await;

    match wallet.sync().await {
        Ok(()) => info!("synced wallet successfully"),
        Err(e) => error!(
            ?e,
            "could not sync wallet before stake funding lookup; still attempting"
        ),
    }

    if let Some(reservation) = output_handles
        .db
        .get_stake_funding_reservation(operator_idx)
        .await?
    {
        info!(%operator_idx, "reusing persisted stake funding reservation");
        validate_reservation(
            &reservation,
            &wallet.reserved_script_pubkey(),
            funding_amount,
        )?;
        let inputs: Vec<OutPoint> = reservation
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect();
        wallet.lease(&inputs);
        return Ok(reservation);
    }

    info!(%operator_idx, "no persisted stake funding reservation; creating a new funding tx");
    let fee_rate = estimate_funding_fee_rate(cfg)?;

    info!(%fee_rate, %funding_amount, "creating stake funding transaction");
    // Stake funding is one reserved-wallet UTXO of `funding_amount`. The reserved-utxo API
    // takes denomination + quantity uniformly (claim-funding pool uses larger quantity
    // with a smaller per-UTXO value); for the stake-funding case it's always quantity 1.
    let funded = wallet
        .create_reserved_utxos(fee_rate, funding_amount, 1)
        .await
        .expect("must be able to create stake funding transaction");
    let reservation = reservation_from_psbt(&funded.psbt);

    info!(%operator_idx, "persisting stake funding reservation");
    if let Err(err) = output_handles
        .db
        .set_stake_funding_reservation(operator_idx, reservation.clone())
        .await
    {
        let new_inputs: Vec<OutPoint> = reservation
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect();

        // If we fail to persist the reservation, we must release the leased outpoints so they can
        // be used
        wallet.release(&new_inputs);
        return Err(err.into());
    }

    Ok(reservation)
}

fn estimate_funding_fee_rate(cfg: &ExecutionConfig) -> Result<FeeRate, ExecutorError> {
    // Floor the current cached fee rate (refreshed in the background by the shared fee source) at
    // `fee::FEE_RATE` so this v3 (TRUC) funding transaction always meets the bridge's hardcoded
    // minimum. The underlying source clamps to >=1 sat/vB; this floor is the bridge-protocol
    // minimum, distinct from the truncation guard.
    let fee_rate = cfg.fee_source.current().max(fee::FEE_RATE);
    info!(%fee_rate, "fee rate for stake funding");

    if fee_rate > cfg.maximum_fee_rate {
        return Err(ExecutorError::FeeRateTooHigh {
            fee_rate,
            max: cfg.maximum_fee_rate,
        });
    }

    Ok(fee_rate)
}

fn validate_reservation(
    reservation: &StakeFundingReservation,
    expected_stake_script: &bitcoin::ScriptBuf,
    expected_funding_amount: Amount,
) -> Result<(), ExecutorError> {
    if reservation.prevouts.len() != reservation.unsigned_tx.input.len() {
        return Err(ExecutorError::InvalidTxStructure(format!(
            "stake funding reservation prevouts ({}) do not match input count ({})",
            reservation.prevouts.len(),
            reservation.unsigned_tx.input.len(),
        )));
    }
    let stake_output = reservation
        .unsigned_tx
        .output
        .get(reservation.stake_output_vout as usize)
        .ok_or_else(|| {
            ExecutorError::InvalidTxStructure(format!(
                "stake funding reservation vout {} out of range ({} outputs)",
                reservation.stake_output_vout,
                reservation.unsigned_tx.output.len(),
            ))
        })?;
    if stake_output.script_pubkey != *expected_stake_script {
        return Err(ExecutorError::InvalidTxStructure(
            "stake funding reservation output script does not match reserved wallet".into(),
        ));
    }
    if stake_output.value != expected_funding_amount {
        return Err(ExecutorError::InvalidTxStructure(format!(
            "stake funding reservation output value {} != expected {}",
            stake_output.value, expected_funding_amount,
        )));
    }
    Ok(())
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
    const DEFAULT_SIGHASH_TYPE: TapSighashType = TapSighashType::Default;

    let input_count = reservation.unsigned_tx.input.len();
    let all_indices: Vec<usize> = (0..input_count).collect();

    // The stake-funding tx is funded entirely from the general wallet, but the reservation is
    // persisted as an unsigned tx + prevouts (the funded PSBT's witnesses, if any, aren't
    // stored), so sign on demand here. A create-and-sign backend (Fireblocks) signs its P2WPKH
    // inputs and returns their witnesses; the native descriptor-only backend returns all `None`
    // and those inputs are signed via secret-service below.
    let backend_witnesses = output_handles
        .wallet
        .read()
        .await
        .sign_owned_inputs(
            &reservation.unsigned_tx,
            &all_indices,
            &reservation.prevouts,
        )
        .await
        .map_err(|e| ExecutorError::WalletErr(format!("backend signing failed: {e}")))?;

    let prevouts = Prevouts::All(&reservation.prevouts);
    let mut sighash_cache = SighashCache::new(&reservation.unsigned_tx);
    let s2_signer = output_handles.s2_client.general_wallet_signer();

    let mut signed_tx = reservation.unsigned_tx.clone();
    for (input_index, backend_witness) in backend_witnesses.iter().enumerate() {
        if let Some(witness) = backend_witness {
            signed_tx.input[input_index].witness = witness.clone();
            continue;
        }
        let sighash = create_key_spend_hash(
            &mut sighash_cache,
            prevouts.clone(),
            DEFAULT_SIGHASH_TYPE,
            input_index,
        )
        .map_err(|e| ExecutorError::WalletErr(format!("key spend hash: {e}")))?;
        let signature = s2_signer
            .sign(sighash.as_ref(), None)
            .await
            .map_err(ExecutorError::SecretServiceErr)?;
        signed_tx.input[input_index]
            .witness
            .push(signature.serialize());
    }

    Ok(signed_tx)
}

pub(crate) async fn publish_unstaking_nonces(
    output_handles: &OutputHandles,
    operator_idx: OperatorIdx,
    graph_inpoints: StakeFunctor<OutPoint>,
    graph_tweaks: StakeFunctor<TaprootTweak>,
    sighashes: StakeFunctor<Message>,
    ordered_pubkeys: Vec<XOnlyPublicKey>,
) -> Result<(), ExecutorError> {
    info!(%operator_idx, "generating and publishing unstaking nonces for the stake graph");

    let musig_signer = output_handles.s2_client.musig2_signer();

    let nonce_futures = StakeFunctor::zip3(graph_inpoints, graph_tweaks, sighashes)
        .into_iter()
        .map(|(inpoint, tweak, sighash)| {
            let params = Musig2Params {
                ordered_pubkeys: ordered_pubkeys.clone(),
                tweak,
                sighash: *sighash.as_ref(),
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
                sighash: *sighash.as_ref(),
            };

            musig_signer
                .get_our_partial_sig(params, agg_nonce)
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

    // The stake tx spends a single funding UTXO in the reserved wallet and is not presigned by
    // the covenant, so key-path sign it with the reserved wallet signer before broadcasting.
    // Reconstruct the prevout from known values: the funding UTXO is always at the reserved
    // address with value `stake_amount + unstaking_intent_output.value() + stake_fee`.
    let reserved_script = output_handles.wallet.read().await.reserved_script_pubkey();
    let funding_amount = stake_funding_amount(cfg.network, cfg.stake_amount);
    let prevout = TxOut {
        script_pubkey: reserved_script,
        value: funding_amount,
    };

    info!(
        %stake_txid,
        %funding_input,
        %funding_amount,
        "signing stake transaction with reserved wallet signer"
    );

    let prevouts = Prevouts::All(&[prevout]);
    let mut sighash_cache = SighashCache::new(tx);
    let sighash = create_key_spend_hash(&mut sighash_cache, prevouts, TapSighashType::Default, 0)
        .expect("must be able to create key spend sighash");

    let signature = output_handles
        .s2_client
        .reserved_wallet_signer()
        .sign(sighash.as_ref(), None)
        .await
        .map_err(ExecutorError::SecretServiceErr)?;

    let mut signed_tx = tx.clone();
    signed_tx.input[0].witness.push(signature.serialize());

    info!(%stake_txid, "publishing signed stake transaction");
    publish_signed_transaction(
        output_handles,
        &signed_tx,
        "stake tx",
        TxStatus::is_buried,
        chain::parent_fee_for_floor_tx(&signed_tx),
        CpfpKind::InferAnchor,
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
