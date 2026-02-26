//! Executors for uncontested payout graph duties.

use algebra::predicate;
use bitcoin::{
    FeeRate, OutPoint, TapSighashType, Transaction, Txid, XOnlyPublicKey,
    sighash::{Prevouts, SighashCache},
};
use bitcoind_async_client::traits::Reader;
use btc_tracker::event::TxStatus;
use futures::{FutureExt, future::try_join_all};
use musig2::{AggNonce, PartialSignature, PubNonce, secp256k1::Message};
use secret_service_proto::v2::traits::{Musig2Params, Musig2Signer, SchnorrSigner, SecretService};
use strata_bridge_db2::{traits::BridgeDb, types::FundingPurpose};
use strata_bridge_primitives::{
    scripts::taproot::{TaprootTweak, TaprootWitness, create_message_hash},
    types::{GraphIdx, OperatorIdx},
};
use strata_bridge_tx_graph2::transactions::claim::ClaimTx;
use tracing::{error, info, warn};

use crate::{
    config::ExecutionConfig, errors::ExecutorError, graph::utils::finalize_claim_funding_tx,
    output_handles::OutputHandles,
};

pub(super) async fn generate_graph_data(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    graph_idx: GraphIdx,
) -> Result<(), ExecutorError> {
    info!(?graph_idx, "generating graph data");
    let OutputHandles {
        wallet,
        db,
        msg_handler2,
        s2_client,
        tx_driver,
        ..
    } = output_handles;

    info!(?graph_idx, "checking if data already exists in disk");
    if let Ok(Some(funding_outpoints)) = db.get_funds(graph_idx, FundingPurpose::Claim).await {
        info!(
            ?graph_idx,
            ?funding_outpoints,
            "graph data already exists in disk, skipping generation"
        );

        // FIXME: (@Rajil1213) Make this a compile-time check by having a separate FDB subspace for
        // claim funding outpoints that holds a single outpoint instead of a vec. For now, we just
        // check that there's exactly one claim input for the graph.
        assert!(
            funding_outpoints.len() == 1,
            "expected exactly one claim input for graph, found {}",
            funding_outpoints.len()
        );

        msg_handler2
            .write()
            .await
            .send_graph_data(graph_idx, funding_outpoints[0], None)
            .await;
    }

    info!(?graph_idx, "fetching funding outpoint from wallet");

    let (funding_outpoint, _remaining) = {
        let mut wallet = wallet.write().await;

        match wallet.sync().await {
            Ok(()) => info!("synced wallet successfully"),
            Err(e) => error!(
                ?e,
                "could not sync wallet before fetching claim funding utxo" /* still safe to
                                                                            * continue
                                                                            * though */
            ),
        }

        let (funding_outpoint, remaining) = wallet.claim_funding_utxo(predicate::never);
        match funding_outpoint {
            Some(outpoint) => (outpoint, remaining),
            None => {
                warn!("could not acquire claim funding utxo. attempting refill...");
                // The first time we run the node, it may be the case that the wallet starts off
                // empty.
                let psbt = wallet.refill_claim_funding_utxos(
                    FeeRate::BROADCAST_MIN,
                    cfg.funding_uxto_pool_size,
                )?;

                // we only wait till the claim funding tx is in the mempool so it is fine to hold
                // the `wallet` lock till that happens.
                finalize_claim_funding_tx(s2_client, tx_driver, wallet.general_wallet(), psbt)
                    .await?;

                wallet.sync().await.map_err(|e| {
                    error!(?e, "could not sync wallet after refilling funding utxos");

                    ExecutorError::WalletErr(format!("wallet sync failed after refill: {e:?}"))
                })?;

                let (funding_op, remaining) = wallet.claim_funding_utxo(predicate::never);

                (
                    funding_op.expect("funding utxos must be available after refill"),
                    remaining,
                )
            }
        }
    };

    info!(?graph_idx, %funding_outpoint, "fetched funding outpoint from wallet, saving to disk");
    db.set_funds(graph_idx, FundingPurpose::Claim, vec![funding_outpoint])
        .await
        .map_err(|e| {
            warn!(?e, "failed to save claim funding outpoint to disk");
            // at this point, it's not safe to broadcast the funding outpoint to other operators, so
            // we return an error and abort the execution.
            match e.to_enum() {
                terrors::E2::A(binding_err) => {
                    ExecutorError::DatabaseErr(format!("fdb binding error: {binding_err:?}"))
                }
                terrors::E2::B(layer_err) => {
                    ExecutorError::DatabaseErr(format!("fdb layer error: {layer_err:?}"))
                }
            }
        })?;

    msg_handler2
        .write()
        .await
        .send_graph_data(graph_idx, funding_outpoint, None)
        .await;

    Ok(())
}

/// Verifies adaptor signatures for the generated graph from a particular watchtower.
///
/// # Warning
///
/// **Not yet implemented.** Currently returns `Ok(())` without performing verification.
/// Requires integration with the mosaic service for actual adaptor verification.
pub(super) async fn verify_adaptors(
    graph_idx: GraphIdx,
    watchtower_idx: OperatorIdx,
    sighashes: &[Message],
) -> Result<(), ExecutorError> {
    info!(
        ?graph_idx,
        %watchtower_idx,
        num_sighashes = sighashes.len(),
        "verifying adaptor signatures"
    );

    // TODO: (mukeshdroid) Integrate with mosaic service for adaptor verification

    info!(
        ?graph_idx,
        %watchtower_idx,
        "adaptor signature verification complete"
    );
    Ok(())
}

/// Publishes nonces for graph transaction signing.
///
/// Generates a MuSig2 public nonce for each graph input and broadcasts them
/// to other operators via P2P.
pub(super) async fn publish_graph_nonces(
    output_handles: &OutputHandles,
    graph_idx: GraphIdx,
    graph_inpoints: &[OutPoint],
    graph_tweaks: &[TaprootTweak],
    ordered_pubkeys: &[XOnlyPublicKey],
) -> Result<(), ExecutorError> {
    info!(?graph_idx, "publishing graph nonces");

    let musig_signer = output_handles.s2_client.musig2_signer();
    let ordered_pubkeys = ordered_pubkeys.to_vec();

    // Generate nonces for each inpoint concurrently
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
                    warn!(?graph_idx, %inpoint, "secret service rejected nonce request: our pubkey missing from params");
                    ExecutorError::OurPubKeyNotInParams
                }),
                Err(e) => {
                    warn!(?graph_idx, %inpoint, ?e, "failed to get pub nonce from secret service");
                    Err(ExecutorError::SecretServiceErr(e))
                }
            })
        });

    let nonces: Vec<PubNonce> = try_join_all(nonce_futures).await?;

    // Broadcast via MessageHandler2
    output_handles
        .msg_handler2
        .write()
        .await
        .send_graph_nonces(graph_idx, nonces, None)
        .await;

    info!(?graph_idx, "graph nonces published");
    Ok(())
}

/// Publishes partial signatures for graph transaction signing.
///
/// Generates a MuSig2 partial signature for each graph input and broadcasts them
/// to other operators via P2P.
#[expect(clippy::too_many_arguments)]
pub(super) async fn publish_graph_partials(
    output_handles: &OutputHandles,
    graph_idx: GraphIdx,
    agg_nonces: &[AggNonce],
    sighashes: &[Message],
    graph_inpoints: &[OutPoint],
    graph_tweaks: &[TaprootTweak],
    claim_txid: Txid,
    ordered_pubkeys: &[XOnlyPublicKey],
) -> Result<(), ExecutorError> {
    // Verify claim tx is NOT on chain before signing partials
    info!(?graph_idx, %claim_txid, "ensuring claim tx is NOT on chain before publishing partials");

    match output_handles
        .bitcoind_rpc_client
        .get_raw_transaction_verbosity_one(&claim_txid)
        .await
    {
        Ok(_) => {
            warn!(?graph_idx, %claim_txid, "claim tx already on chain, aborting partial sig generation");
            return Err(ExecutorError::ClaimTxAlreadyOnChain(claim_txid));
        }
        Err(e) if e.is_tx_not_found() => { /* safe to proceed */ }
        Err(e) => {
            warn!(?graph_idx, %claim_txid, ?e, "failed to check claim tx status, aborting partial sig generation");
            return Err(ExecutorError::BitcoinRpcErr(e));
        }
    }

    info!(?graph_idx, %claim_txid, num_inputs = graph_inpoints.len(), "publishing graph partials");

    let musig_signer = output_handles.s2_client.musig2_signer();
    let ordered_pubkeys = ordered_pubkeys.to_vec();

    // Generate partial signatures for each input concurrently
    let partial_futures = graph_inpoints
        .iter()
        .zip(graph_tweaks.iter())
        .zip(agg_nonces.iter())
        .zip(sighashes.iter())
        .map(|(((inpoint, tweak), agg_nonce), sighash)| {
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
                        warn!(?graph_idx, %inpoint, "secret service rejected partial sig request: our pubkey missing from params");
                        ExecutorError::OurPubKeyNotInParams
                    }
                    terrors::E2::B(_) => {
                        warn!(?graph_idx, %inpoint, "secret service rejected partial sig request: self-verification failed");
                        ExecutorError::SelfVerifyFailed
                    }
                }),
                Err(e) => {
                    warn!(?graph_idx, %inpoint, ?e, "failed to get partial sig from secret service");
                    Err(ExecutorError::SecretServiceErr(e))
                }
            })
    });

    let partials: Vec<PartialSignature> = try_join_all(partial_futures).await?;

    // Broadcast via MessageHandler2
    output_handles
        .msg_handler2
        .write()
        .await
        .send_graph_partials(graph_idx, partials, None)
        .await;

    info!(?graph_idx, "graph partials published");
    Ok(())
}

/// Publishes the claim transaction to Bitcoin.
pub(super) async fn publish_claim(
    output_handles: &OutputHandles,
    claim_tx: &ClaimTx,
) -> Result<(), ExecutorError> {
    let unsigned_claim_tx = claim_tx.as_ref().clone();
    let claim_txid = unsigned_claim_tx.compute_txid();
    info!(
        %claim_txid,
        "signing claim transaction"
    );

    let claim_prevout = {
        let wallet = output_handles.wallet.read().await;
        wallet
            .claim_funding_outputs()
            .find(|utxo| utxo.outpoint == claim_tx.as_ref().input[0].previous_output)
            .expect("claim funding outpoint not found in wallet")
            .txout
    };

    let prevouts = Prevouts::All(&[claim_prevout]);

    let mut sighash_cache = SighashCache::new(&unsigned_claim_tx);
    let mut signed_claim_tx = unsigned_claim_tx.clone();
    for (input_index, _) in unsigned_claim_tx.input.iter().enumerate() {
        let msg = create_message_hash(
            &mut sighash_cache,
            prevouts.clone(),
            &TaprootWitness::Key,
            TapSighashType::Default,
            input_index,
        )
        .map_err(|e| {
            warn!(
                %claim_txid,
                input_index,
                %e,
                "failed to create claim input sighash"
            );
            ExecutorError::WalletErr(format!("sighash error: {e}"))
        })?;

        // TODO: (mukeshdroid) We want to ensure the funding UTXO for the claim to be preserved.
        // This means that we should not use the general_wallet. Stakechain_signer wallet
        // has been used as a placeholder for non-general wallet. This implies that the funding
        // outputs should also be generated from the stakechain_signer wallet.
        let signature = output_handles
            .s2_client
            .stakechain_wallet_signer()
            .sign(msg.as_ref(), None)
            .await
            .map_err(|e| {
                warn!(
                    %claim_txid,
                    input_index,
                    ?e,
                    "failed to sign claim input"
                );
                ExecutorError::SecretServiceErr(e)
            })?;
        signed_claim_tx.input[input_index]
            .witness
            .push(signature.serialize());
    }

    info!(%claim_txid, "Publishing claim transaction");
    output_handles
        .tx_driver
        .drive(signed_claim_tx, TxStatus::is_buried)
        .await
        .map_err(|e| {
            warn!(%claim_txid, ?e, "failed to publish claim transaction");
            ExecutorError::TxDriverErr(e)
        })?;

    info!(%claim_txid, "claim transaction confirmed");
    Ok(())
}

/// Publishes the signed uncontested payout transaction to Bitcoin.
pub(super) async fn publish_uncontested_payout(
    output_handles: &OutputHandles,
    signed_uncontested_payout_tx: &Transaction,
) -> Result<(), ExecutorError> {
    let payout_txid = signed_uncontested_payout_tx.compute_txid();
    info!(%payout_txid, "publishing uncontested payout transaction");

    output_handles
        .tx_driver
        .drive(signed_uncontested_payout_tx.clone(), TxStatus::is_buried)
        .await
        .map_err(|e| {
            warn!(%payout_txid, ?e, "failed to publish uncontested payout transaction");
            ExecutorError::TxDriverErr(e)
        })?;

    info!(%payout_txid, "uncontested payout confirmed");
    Ok(())
}
