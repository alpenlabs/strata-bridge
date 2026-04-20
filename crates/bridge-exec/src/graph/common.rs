//! Executors for uncontested payout graph duties.

use std::num::NonZero;

use algebra::predicate;
use bitcoin::{
    FeeRate, OutPoint, TapSighashType, Txid, XOnlyPublicKey,
    hashes::sha256,
    sighash::{Prevouts, SighashCache},
};
use btc_tracker::event::TxStatus;
use futures::{FutureExt, future::try_join_all};
use musig2::{AggNonce, PartialSignature, PubNonce, secp256k1::Message};
use secret_service_proto::v2::traits::{Musig2Params, Musig2Signer, SchnorrSigner, SecretService};
use strata_bridge_db::traits::BridgeDb;
use strata_bridge_p2p_types::{GraphData, XOnlyPubKey};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    scripts::taproot::{TaprootTweak, TaprootWitness, create_message_hash},
    types::{GraphIdx, OperatorIdx},
};
use strata_bridge_sm::graph::{context::GraphSMCtx, machine::generate_game_graph};
use strata_bridge_tx_graph::{
    game_graph::{DepositParams, GameGraph},
    transactions::claim::ClaimTx,
};
use strata_mosaic_client_api::{
    MosaicClientApi,
    types::{DepositSighashes, Role, Sighash},
};
use tracing::{error, info, warn};

use super::utils::finalize_claim_funding_tx;
use crate::{
    chain::{is_txid_onchain, publish_signed_transaction},
    config::ExecutionConfig,
    errors::ExecutorError,
    output_handles::OutputHandles,
};

pub(super) async fn generate_graph_data(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    graph_idx: GraphIdx,
    deposit_outpoint: OutPoint,
    stake_outpoint: OutPoint,
    unstaking_image: sha256::Hash,
) -> Result<(), ExecutorError> {
    info!(
        ?graph_idx,
        %deposit_outpoint,
        %stake_outpoint,
        "generating graph data"
    );

    let funding_outpoint = ensure_claim_funding_outpoint(cfg, output_handles, graph_idx).await?;
    info!(?graph_idx, %funding_outpoint, "funding outpoint acquired");

    let (adaptor_pubkey, fault_pubkeys) = fetch_graph_keys(
        output_handles.mosaic_client.as_ref(),
        &output_handles.operator_table,
        graph_idx,
    )
    .await?;
    info!(
        ?graph_idx,
        ?adaptor_pubkey,
        n_fault_pubkeys = fault_pubkeys.len(),
        "fetched graph keys from mosaic"
    );

    let ctx = GraphSMCtx {
        graph_idx,
        deposit_outpoint,
        stake_outpoint,
        unstaking_image,
        operator_table: output_handles.operator_table.clone(),
    };
    let deposit_params = DepositParams {
        game_index: NonZero::new(graph_idx.deposit + 1)
            .expect("(deposit index + 1) is always non-zero"),
        claim_funds: funding_outpoint,
        deposit_outpoint,
        adaptor_pubkey: adaptor_pubkey.try_into().map_err(invalid_mosaic_key)?,
        fault_pubkeys: fault_pubkeys
            .iter()
            .copied()
            .map(XOnlyPublicKey::try_from)
            .collect::<Result<_, _>>()
            .map_err(invalid_mosaic_key)?,
    };
    let game_graph = generate_game_graph(&cfg.graph_sm_cfg, &ctx, &deposit_params);
    info!(?graph_idx, "game graph constructed");

    init_evaluator_with_peers(
        output_handles.mosaic_client.as_ref(),
        &output_handles.operator_table,
        graph_idx,
        &game_graph,
    )
    .await?;
    info!(
        ?graph_idx,
        "evaluator deposits initialized with all watchtowers"
    );

    let graph_data = GraphData::new(funding_outpoint, adaptor_pubkey, fault_pubkeys);
    output_handles
        .msg_handler
        .write()
        .await
        .send_graph_data(graph_idx, graph_data, None)
        .await;
    info!(?graph_idx, "broadcasted graph data");

    Ok(())
}

fn invalid_mosaic_key(err: bitcoin::secp256k1::Error) -> ExecutorError {
    ExecutorError::MosaicErr(format!("invalid mosaic pubkey: {err:?}"))
}

/// Returns the claim-funding outpoint for `graph_idx`, fetching it from the wallet (refilling
/// if necessary) and caching to disk when not already saved.
async fn ensure_claim_funding_outpoint(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    graph_idx: GraphIdx,
) -> Result<OutPoint, ExecutorError> {
    if let Ok(Some(funding_outpoint)) = output_handles
        .db
        .get_claim_funding_outpoint(graph_idx)
        .await
    {
        info!(
            ?graph_idx,
            ?funding_outpoint,
            "reusing cached funding outpoint"
        );
        return Ok(funding_outpoint);
    }

    info!(?graph_idx, "fetching funding outpoint from wallet");
    let funding_outpoint = {
        let mut wallet = output_handles.wallet.write().await;

        match wallet.sync().await {
            Ok(()) => info!("synced wallet successfully"),
            Err(e) => error!(
                ?e,
                "could not sync wallet before fetching claim funding utxo"
            ),
        }

        match wallet.claim_funding_utxo(predicate::never).0 {
            Some(outpoint) => outpoint,
            None => {
                warn!("could not acquire claim funding utxo. attempting refill...");
                let psbt = wallet.refill_claim_funding_utxos(
                    FeeRate::BROADCAST_MIN,
                    cfg.funding_uxto_pool_size,
                )?;
                finalize_claim_funding_tx(
                    &output_handles.s2_client,
                    &output_handles.tx_driver,
                    wallet.general_wallet(),
                    psbt,
                )
                .await?;
                wallet.sync().await.map_err(|e| {
                    error!(?e, "could not sync wallet after refilling funding utxos");
                    ExecutorError::WalletErr(format!("wallet sync failed after refill: {e:?}"))
                })?;
                wallet
                    .claim_funding_utxo(predicate::never)
                    .0
                    .expect("funding utxos must be available after refill")
            }
        }
    };

    info!(?graph_idx, %funding_outpoint, "saving funding outpoint to disk");
    output_handles
        .db
        .set_claim_funding_outpoint(graph_idx, funding_outpoint)
        .await?;

    Ok(funding_outpoint)
}

/// Fetches the owner's adaptor pubkey and the per-watchtower fault pubkeys from mosaic.
///
/// The adaptor pubkey belongs to the graph owner (evaluator) and is queried against the
/// owner's own peer id. Each watchtower contributes one fault pubkey, queried against that
/// watchtower's peer id with own role `Evaluator`.
async fn fetch_graph_keys(
    mosaic_client: &dyn MosaicClientApi,
    operator_table: &OperatorTable,
    graph_idx: GraphIdx,
) -> Result<(XOnlyPubKey, Vec<XOnlyPubKey>), ExecutorError> {
    let owner_idx = graph_idx.operator;

    info!(?graph_idx, %owner_idx, "fetching adaptor pubkey from mosaic");
    let adaptor_pubkey = mosaic_client
        .get_adaptor_pubkey(owner_idx, graph_idx.deposit)
        .await
        .map_err(|e| ExecutorError::MosaicErr(format!("get_adaptor_pubkey: {e:?}")))?
        .ok_or_else(|| ExecutorError::MosaicErr("adaptor pubkey missing for ready setup".into()))?;

    let mut fault_pubkeys = Vec::new();
    for watchtower in watchtower_idxs(operator_table, owner_idx) {
        info!(?graph_idx, %watchtower, "fetching fault pubkey from mosaic");
        let fault_pubkey = mosaic_client
            .get_fault_pubkey(watchtower, Role::Evaluator)
            .await
            .map_err(|e| ExecutorError::MosaicErr(format!("get_fault_pubkey: {e:?}")))?
            .ok_or_else(|| {
                ExecutorError::MosaicErr(format!(
                    "fault pubkey missing for watchtower {watchtower}"
                ))
            })?;
        fault_pubkeys.push(fault_pubkey.into());
    }

    Ok((adaptor_pubkey.into(), fault_pubkeys))
}

/// Pulls per-watchtower counterproof sighashes from `game_graph` and calls
/// `init_evaluator_deposit` on mosaic for each watchtower peer.
async fn init_evaluator_with_peers(
    mosaic_client: &dyn MosaicClientApi,
    operator_table: &OperatorTable,
    graph_idx: GraphIdx,
    game_graph: &GameGraph,
) -> Result<(), ExecutorError> {
    for (slot, watchtower_idx) in watchtower_idxs(operator_table, graph_idx.operator).enumerate() {
        let sighashes = game_graph.counterproofs[slot].counterproof.sighashes();
        info!(
            ?graph_idx,
            %watchtower_idx,
            n_sighashes = sighashes.len(),
            "computed counterproof sighashes"
        );
        let deposit_sighashes: DepositSighashes = sighashes
            .iter()
            .map(|m| *m.as_ref())
            .collect::<Vec<Sighash>>()
            .try_into()
            .map_err(|v: Vec<Sighash>| {
                ExecutorError::MosaicErr(format!(
                    "counterproof produced {} sighashes, expected {}",
                    v.len(),
                    std::mem::size_of::<DepositSighashes>() / std::mem::size_of::<Sighash>()
                ))
            })?;

        info!(?graph_idx, %watchtower_idx, "calling mosaic init_evaluator_deposit");
        mosaic_client
            .init_evaluator_deposit(watchtower_idx, graph_idx.deposit, deposit_sighashes)
            .await
            .map_err(|e| ExecutorError::MosaicErr(format!("init_evaluator_deposit: {e:?}")))?;
        info!(?graph_idx, %watchtower_idx, "mosaic init_evaluator_deposit ok");
    }

    Ok(())
}

/// Returns the watchtower (non-owner) operator indices in operator-table order.
fn watchtower_idxs(
    operator_table: &OperatorTable,
    owner_idx: OperatorIdx,
) -> impl Iterator<Item = OperatorIdx> + '_ {
    operator_table
        .operator_idxs()
        .into_iter()
        .filter(move |idx| *idx != owner_idx)
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

    // TODO: <https://alpenlabs.atlassian.net/browse/STR-2669>
    // Integrate with the mosaic service for adaptor verification.

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

    // Broadcast via MessageHandler
    output_handles
        .msg_handler
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
    info!(
        ?graph_idx,
        %claim_txid,
        "ensuring claim tx is not on chain before publishing partials"
    );
    if is_txid_onchain(&output_handles.bitcoind_rpc_client, &claim_txid)
        .await
        .map_err(ExecutorError::BitcoinRpcErr)?
    {
        warn!(
            ?graph_idx,
            %claim_txid,
            "claim tx already on chain, aborting partial sig generation"
        );
        return Err(ExecutorError::ClaimTxAlreadyOnChain(claim_txid));
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

    // Broadcast via MessageHandler
    output_handles
        .msg_handler
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

        // NOTE: (mukeshdroid) Preserve the funding UTXO for the claim.
        // This means we should not use the general wallet. `stakechain_signer` is currently used
        // as a placeholder non-general wallet, so the funding outputs should also be generated
        // from the `stakechain_signer` wallet.
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

    publish_signed_transaction(
        &output_handles.tx_driver,
        &signed_claim_tx,
        "claim",
        TxStatus::is_buried,
    )
    .await
}
