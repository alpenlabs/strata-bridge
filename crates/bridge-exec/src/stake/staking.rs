//! Duties related to staking.
//!
//! This covers all duties related to the collection of unstaking signatures upto the publication of
//! the stake transaction.

use bitcoin::{
    Address, FeeRate, OutPoint, Psbt, TapSighashType, Transaction,
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
use strata_bridge_p2p_types::UnstakingInput;
use strata_bridge_primitives::{
    scripts::taproot::{TaprootTweak, create_key_spend_hash, finalize_input},
    types::OperatorIdx,
};
use strata_bridge_tx_graph::stake_graph::StakeGraph;
use tracing::{info, warn};

use crate::{
    chain::publish_signed_transaction, config::ExecutionConfig, errors::ExecutorError,
    output_handles::OutputHandles, stake::utils::get_preimage,
};

pub(crate) async fn publish_stake_data(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    operator_idx: OperatorIdx,
) -> Result<(), ExecutorError> {
    // Create stake funding transaction
    let wallet = output_handles.wallet.read().await;

    info!("checking if there is an existing stake funding transaction");
    let stake_funds = if let Some(out) = wallet.s_utxo() {
        drop(wallet); // drop lock
        info!(outpoint=%out.outpoint, "found existing stake funding transaction");
        out.outpoint
    } else {
        drop(wallet); // drop read lock before acquiring write lock in create_stake_funding_tx
        info!("no existing stake funding transaction found, creating a new one");
        let stake_funding_tx = create_stake_funding_tx(output_handles).await?;

        OutPoint {
            txid: stake_funding_tx.compute_txid(),
            vout: 0, // there is only one output in the stake funding transaction.
        }
    };

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

async fn create_stake_funding_tx(
    output_handles: &OutputHandles,
) -> Result<Transaction, ExecutorError> {
    const DEFAULT_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(5);

    info!("fetching fee rate from bitcoind");
    let fee_rate = output_handles
        .bitcoind_rpc_client
        .estimate_smart_fee(1)
        .await?;

    let fee_rate = FeeRate::from_sat_per_vb(fee_rate).unwrap_or(DEFAULT_FEE_RATE);

    info!(%fee_rate, "creating stake funding transaction");
    let psbt = {
        let mut wallet = output_handles.wallet.write().await;

        wallet
            .create_stake_funding_tx(fee_rate)
            .expect("must be able to create stake funding transaction")
    };

    info!("signing stake funding transaction via secret-service");
    let stake_funding_tx = sign_with_general_wallet(output_handles, psbt).await?;

    info!("publishing stake funding transaction");
    publish_signed_transaction(
        &output_handles.tx_driver,
        &stake_funding_tx,
        "stake funding tx",
        TxStatus::is_buried,
    )
    .await?;

    Ok(stake_funding_tx)
}

async fn sign_with_general_wallet(
    output_handles: &OutputHandles,
    mut psbt: Psbt,
) -> Result<Transaction, ExecutorError> {
    let prevouts = Prevouts::All(
        &psbt
            .inputs
            .iter()
            .map(|input| {
                input
                    .witness_utxo
                    .as_ref()
                    .expect("must have witness utxo")
                    .to_owned()
            })
            .collect::<Vec<_>>(),
    );

    const DEFAULT_SIGHASH_TYPE: TapSighashType = TapSighashType::Default;

    let mut sighash_cache = SighashCache::new(&psbt.unsigned_tx);
    let sighashes = psbt.inputs.iter().enumerate().map(|(input_index, input)| {
        let prevout_sighash_type = input.sighash_type.unwrap_or(DEFAULT_SIGHASH_TYPE.into());
        create_key_spend_hash(
            &mut sighash_cache,
            prevouts.clone(),
            prevout_sighash_type
                .taproot_hash_ty()
                .unwrap_or(DEFAULT_SIGHASH_TYPE),
            input_index,
        )
        .expect("must be able to create key spend hash")
    });

    let s2_signer = output_handles.s2_client.general_wallet_signer();
    let mut signatures = vec![];
    for sighash in sighashes {
        let signature = s2_signer
            .sign(sighash.as_ref(), None)
            .await
            .map_err(ExecutorError::SecretServiceErr)?;

        signatures.push(signature);
    }
    psbt.inputs
        .iter_mut()
        .zip(signatures)
        .for_each(|(input, signature)| {
            let witness = signature.serialize();
            finalize_input(input, [witness]);
        });

    let signed_tx = psbt
        .extract_tx()
        .expect("must be able to extract signed funding transaction");

    Ok(signed_tx)
}

pub(crate) async fn publish_unstaking_nonces(
    output_handles: &OutputHandles,
    operator_idx: OperatorIdx,
    graph_inpoints: [bitcoin::OutPoint; StakeGraph::N_MUSIG_INPUTS],
    graph_tweaks: [TaprootTweak; StakeGraph::N_MUSIG_INPUTS],
    ordered_pubkeys: Vec<XOnlyPublicKey>,
) -> Result<(), ExecutorError> {
    info!(%operator_idx, "generating and publishing unstaking nonces for the stake graph");

    let musig_signer = output_handles.s2_client.musig2_signer();

    let nonce_futures = graph_inpoints
        .iter()
        .zip(graph_tweaks.iter())
        .map(|(inpoint, tweak)| {
            let params = Musig2Params {
                ordered_pubkeys: ordered_pubkeys.clone(),
                tweak: *tweak,
                input: *inpoint,
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
    graph_inpoints: [bitcoin::OutPoint; StakeGraph::N_MUSIG_INPUTS],
    graph_tweaks: [TaprootTweak; StakeGraph::N_MUSIG_INPUTS],
    sighashes: [Message; StakeGraph::N_MUSIG_INPUTS],
    agg_nonces: &[AggNonce; StakeGraph::N_MUSIG_INPUTS],
    ordered_pubkeys: Vec<XOnlyPublicKey>,
) -> Result<(), ExecutorError> {
    info!(%operator_idx, "generating and publishing unstaking partial signatures for the stake graph");

    let musig_signer = output_handles.s2_client.musig2_signer();
    let partial_futures = graph_inpoints
        .iter()
        .zip(graph_tweaks.iter())
        .zip(sighashes.iter())
        .zip(agg_nonces.iter())
        .map(|(((inpoint, tweak), sighash), agg_nonce)| {
            let params = Musig2Params {
                ordered_pubkeys: ordered_pubkeys.clone(),
                tweak: *tweak,
                input: *inpoint,
            };

            musig_signer
                .get_our_partial_sig(params, agg_nonce.clone(), *sighash.as_ref())
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
    output_handles: &OutputHandles,
    tx: &Transaction,
) -> Result<(), ExecutorError> {
    publish_signed_transaction(
        &output_handles.tx_driver,
        tx,
        "stake tx",
        TxStatus::is_buried,
    )
    .await
}
