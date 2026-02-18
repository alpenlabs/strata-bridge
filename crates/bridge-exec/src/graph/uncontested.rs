//! Executors for uncontested payout graph duties.

use bitcoin::{OutPoint, Transaction, Txid, XOnlyPublicKey};
use bitcoind_async_client::traits::Reader;
use btc_tracker::event::TxStatus;
use futures::{FutureExt, future::try_join_all};
use musig2::{AggNonce, PartialSignature, PubNonce, secp256k1::Message};
use secret_service_proto::v2::traits::{Musig2Params, Musig2Signer, SecretService};
use strata_bridge_primitives::{
    scripts::taproot::TaprootTweak,
    types::{GraphIdx, OperatorIdx},
};
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

    // TODO (mukeshdroid): Integrate with mosaic service for adaptor verification

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
    let partial_futures = (0..graph_inpoints.len()).map(|i| {
        let params = Musig2Params {
            ordered_pubkeys: ordered_pubkeys.clone(),
            tweak: graph_tweaks[i],
            input: graph_inpoints[i],
        };
        let inpoint = graph_inpoints[i];
        musig_signer
            .get_our_partial_sig(params, agg_nonces[i].clone(), *sighashes[i].as_ref())
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

/// Publishes the signed claim transaction to Bitcoin.
pub(super) async fn publish_claim(
    output_handles: &OutputHandles,
    signed_claim_tx: &Transaction,
) -> Result<(), ExecutorError> {
    let claim_txid = signed_claim_tx.compute_txid();
    info!(%claim_txid, "publishing claim transaction");

    output_handles
        .tx_driver
        .drive(signed_claim_tx.clone(), TxStatus::is_buried)
        .await
        .map_err(|e| {
            warn!(%claim_txid, ?e, "failed to publish claim transaction");
            ExecutorError::TxDriverErr(e)
        })?;

    info!(%claim_txid, "claim transaction confirmed");
    Ok(())
}
