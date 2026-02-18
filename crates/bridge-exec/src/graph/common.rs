//! Executors for uncontested payout graph duties.

use bitcoin::{
    OutPoint, TapSighashType, Txid, XOnlyPublicKey,
    sighash::{Prevouts, SighashCache},
};
use bitcoind_async_client::traits::Reader;
use btc_tracker::event::TxStatus;
use futures::{FutureExt, future::try_join_all};
use musig2::{AggNonce, PartialSignature, PubNonce, secp256k1::Message};
use secret_service_proto::v2::traits::{Musig2Params, Musig2Signer, SchnorrSigner, SecretService};
use strata_bridge_primitives::{
    scripts::taproot::{TaprootTweak, TaprootWitness, create_message_hash},
    types::{GraphIdx, OperatorIdx},
};
use strata_bridge_tx_graph2::transactions::claim::ClaimTx;
use tracing::{info, warn};

use crate::{errors::ExecutorError, output_handles::OutputHandles};

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

    // TODO: (mukeshdroid) Currently, we need to fetch the prevouts form the bitcoind
    // since the ClaimTx doesn't contain this info. Updating ClaimTx and adding signing_info
    // method would simplify the executor.
    let prevout_futures = unsigned_claim_tx.input.iter().map(|input| {
        output_handles.bitcoind_rpc_client.get_tx_out(
            &input.previous_output.txid,
            input.previous_output.vout,
            true,
        )
    });
    let prevouts = try_join_all(prevout_futures)
        .await
        .map_err(|e| {
            warn!(%claim_txid, ?e, "failed to fetch claim input prevouts");
            ExecutorError::BitcoinRpcErr(e)
        })?
        .into_iter()
        .map(|utxo| utxo.tx_out)
        .collect::<Vec<_>>();
    let prevouts = Prevouts::All(&prevouts);

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
        // outputs should also be generated fromt the stakechain_signer wallet.
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
