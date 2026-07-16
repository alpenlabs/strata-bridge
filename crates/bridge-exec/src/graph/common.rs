//! Executors for uncontested payout graph duties.

use std::collections::BTreeSet;

use algebra::predicate;
use bitcoin::{
    OutPoint, TapSighashType, TxOut, Txid, XOnlyPublicKey,
    hashes::sha256,
    sighash::{Prevouts, SighashCache},
};
use btc_tracker::event::TxStatus;
use futures::{FutureExt, future::try_join_all};
use musig2::{AggNonce, PartialSignature, PubNonce, secp256k1::Message};
use operator_wallet::{GeneralUtxoPolicy, GeneralWallet, OperatorWallet, UtxoInfo};
use secret_service_proto::v2::traits::{Musig2Params, Musig2Signer, SchnorrSigner, SecretService};
use strata_bridge_db::{traits::BridgeDb, types::FundingAssignment};
use strata_bridge_p2p_types::{GraphData, XOnlyPubKey};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    scripts::taproot::{TaprootTweak, TaprootWitness, create_message_hash},
    types::{GameIndex, GraphIdx, OperatorIdx},
};
use strata_bridge_sm::graph::{context::GraphSMCtx, machine::generate_game_graph};
use strata_bridge_tx_graph::{
    fee,
    game_graph::{DepositParams, GameGraph},
    transactions::claim::ClaimTx,
};
use strata_mosaic_client_api::{
    MosaicClientApi,
    types::{DepositSighashes, Role, Sighash},
};
use tracing::{error, info, warn};

use super::utils::sign_claim_funding_tx;
use crate::{
    chain::{is_outpoint_unspent, is_txid_onchain, publish_signed_transaction},
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
    operator_table: &OperatorTable,
) -> Result<(), ExecutorError> {
    info!(
        ?graph_idx,
        %deposit_outpoint,
        %stake_outpoint,
        "generating graph data"
    );

    let game_index = GameIndex::try_from(graph_idx.deposit)
        .expect("deposit index does not overflow when mapped to game index");

    let funding_outpoint = ensure_claim_funding_outpoint(cfg, output_handles, graph_idx).await?;
    info!(?graph_idx, %funding_outpoint, "funding outpoint acquired");

    let (adaptor_pubkeys, fault_pubkeys) = fetch_graph_keys(
        output_handles.mosaic_client.as_ref(),
        operator_table,
        graph_idx,
        game_index,
    )
    .await?;
    info!(
        ?graph_idx,
        n_adaptor_pubkeys = adaptor_pubkeys.len(),
        n_fault_pubkeys = fault_pubkeys.len(),
        "fetched graph keys from mosaic"
    );

    let ctx = GraphSMCtx {
        graph_idx,
        deposit_outpoint,
        stake_outpoint,
        unstaking_image,
        operator_table: operator_table.clone(),
    };
    let deposit_params = DepositParams {
        game_index: game_index.into(),
        claim_funds: funding_outpoint,
        deposit_outpoint,
        adaptor_pubkeys: adaptor_pubkeys
            .iter()
            .copied()
            .map(XOnlyPublicKey::try_from)
            .collect::<Result<_, _>>()
            .map_err(invalid_mosaic_key)?,
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
        operator_table,
        graph_idx,
        game_index,
        &game_graph,
    )
    .await?;
    info!(
        ?graph_idx,
        "evaluator deposits initialized with all watchtowers"
    );

    let graph_data = GraphData::new(funding_outpoint, adaptor_pubkeys, fault_pubkeys);
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

        match wallet
            .reserve_utxo_with_value(cfg.claim_funding_utxo_value, predicate::never::<UtxoInfo>)
            .0
        {
            Some(outpoint) => outpoint,
            None => {
                warn!("could not acquire claim funding utxo. attempting refill...");
                // How many we need to top the pool back up to the configured target. We
                // compute the batch ourselves (the wallet stays denomination-agnostic),
                // counting only *unleased* pool members: `reserved_utxos_with_value`
                // returns every matching UTXO including leased ones, but a leased UTXO is
                // already committed to another graph and can't satisfy this reservation.
                // Counting them would understate the deficit and could yield a zero-size
                // batch, after which the post-refill `reserve_utxo_with_value` below would
                // panic with nothing to hand out.
                let current_pool_size = {
                    let pool = wallet.reserved_utxos_with_value(cfg.claim_funding_utxo_value);
                    let leased = wallet.leased_outpoints();
                    pool.iter()
                        .filter(|u| !leased.contains(&u.outpoint))
                        .count()
                };
                let batch_size = cfg.funding_uxto_pool_size.saturating_sub(current_pool_size);
                let funded = wallet
                    .create_reserved_utxos(
                        fee::FEE_RATE,
                        cfg.claim_funding_utxo_value,
                        batch_size,
                        GeneralUtxoPolicy::ConfirmedOnly,
                    )
                    .await
                    .map_err(|e| ExecutorError::WalletErr(format!("refill failed: {e}")))?;
                let spent = funded.spent();
                let tx = match sign_claim_funding_tx(&output_handles.s2_client, funded.psbt).await {
                    Ok(tx) => tx,
                    Err(err) => {
                        wallet.release(&spent);
                        warn!(
                            ?err,
                            ?spent,
                            "claim-funding refill signing failed; released inputs"
                        );

                        return Err(err);
                    }
                };
                let txid = tx.compute_txid();
                info!(%txid, "submitting claim funding tx to the tx driver");
                if let Err(err) = output_handles
                    .tx_driver
                    .drive(tx, predicate::eq(TxStatus::Mempool))
                    .await
                {
                    warn!(
                        ?err,
                        ?spent,
                        "claim-funding tx driver failed; syncing wallet before reconciling input leases"
                    );
                    reconcile_claim_funding_leases_after_driver_failure(&mut wallet, &spent).await;

                    return Err(err.into());
                }
                info!(%txid, "claim funding tx detected in mempool");

                wallet.sync().await.map_err(|e| {
                    error!(?e, "could not sync wallet after refilling funding utxos");
                    ExecutorError::WalletErr(format!("wallet sync failed after refill: {e:?}"))
                })?;
                wallet
                    .reserve_utxo_with_value(
                        cfg.claim_funding_utxo_value,
                        predicate::never::<UtxoInfo>,
                    )
                    .0
                    .expect("funding utxos must be available after refill")
            }
        }
    };

    let assignment = output_handles
        .db
        .get_or_set_claim_funding_outpoint(graph_idx, funding_outpoint)
        .await;

    let assigned_outpoint = match assignment {
        Ok(FundingAssignment::Created(outpoint)) => {
            info!(?graph_idx, %outpoint, "saved funding outpoint to disk");
            outpoint
        }
        Ok(FundingAssignment::Existing(outpoint)) => {
            info!(
                ?graph_idx,
                %outpoint,
                "using existing funding outpoint saved by another duty"
            );
            if outpoint != funding_outpoint {
                let mut wallet = output_handles.wallet.write().await;
                wallet.release(&[funding_outpoint]);
            }
            outpoint
        }
        Err(err) => {
            let mut wallet = output_handles.wallet.write().await;
            wallet.release(&[funding_outpoint]);
            return Err(err.into());
        }
    };

    Ok(assigned_outpoint)
}

async fn reconcile_claim_funding_leases_after_driver_failure<G: GeneralWallet>(
    wallet: &mut OperatorWallet<G>,
    spent: &[OutPoint],
) {
    if let Err(sync_err) = wallet.sync().await {
        warn!(
            ?sync_err,
            ?spent,
            "could not sync wallet after tx-driver failure; retaining claim-funding input leases"
        );
        return;
    }

    let live_general_outpoints: BTreeSet<_> = wallet
        .general()
        .list_utxos()
        .into_iter()
        .map(|u| u.outpoint)
        .collect();
    let still_unspent: Vec<_> = spent
        .iter()
        .copied()
        .filter(|outpoint| live_general_outpoints.contains(outpoint))
        .collect();
    let pruned_count = spent.len().saturating_sub(still_unspent.len());

    if pruned_count > 0 {
        info!(
            pruned_count,
            "wallet sync pruned claim-funding input leases no longer seen as spendable"
        );
    }
    if !still_unspent.is_empty() {
        wallet.release(&still_unspent);
        warn!(
            ?still_unspent,
            "released claim-funding input leases after wallet sync showed they are still spendable"
        );
    }
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
    game_index: GameIndex,
) -> Result<(Vec<XOnlyPubKey>, Vec<XOnlyPubKey>), ExecutorError> {
    let owner_idx = graph_idx.operator;

    // Mosaic exposes a distinct adaptor secret per `(evaluator, garbler)` tableset, so the owner
    // has one adaptor pubkey per watchtower. Collect them in operator-table order (owner
    // skipped). The per-watchtower fault pubkey comes from the same tableset.
    let mut adaptor_pubkeys = Vec::new();
    let mut fault_pubkeys = Vec::new();
    for watchtower in watchtower_idxs(operator_table, owner_idx) {
        info!(?graph_idx, %game_index, %watchtower, "fetching adaptor pubkey from mosaic");
        let adaptor = mosaic_client
            .get_adaptor_pubkey(watchtower, game_index)
            .await
            .map_err(|e| ExecutorError::MosaicErr(format!("get_adaptor_pubkey: {e:?}")))?
            .ok_or_else(|| {
                ExecutorError::MosaicErr(format!(
                    "adaptor pubkey missing for watchtower {watchtower}"
                ))
            })?;
        adaptor_pubkeys.push(adaptor.into());

        info!(?graph_idx, %game_index, %watchtower, "fetching fault pubkey from mosaic");
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

    if adaptor_pubkeys.is_empty() {
        return Err(ExecutorError::MosaicErr(
            "operator table has no peers".into(),
        ));
    }
    Ok((adaptor_pubkeys, fault_pubkeys))
}

/// Pulls per-watchtower counterproof sighashes from `game_graph` and calls
/// `init_evaluator_deposit` on mosaic for each watchtower peer.
async fn init_evaluator_with_peers(
    mosaic_client: &dyn MosaicClientApi,
    operator_table: &OperatorTable,
    graph_idx: GraphIdx,
    game_index: GameIndex,
    game_graph: &GameGraph,
) -> Result<(), ExecutorError> {
    for (slot, watchtower_idx) in watchtower_idxs(operator_table, graph_idx.operator).enumerate() {
        let sighashes = game_graph.counterproofs[slot].counterproof.sighashes();
        info!(
            ?graph_idx,
            %game_index,
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

        info!(?graph_idx, %game_index, %watchtower_idx, "calling mosaic init_evaluator_deposit");
        mosaic_client
            .init_evaluator_deposit(watchtower_idx, game_index, deposit_sighashes)
            .await
            .map_err(|e| ExecutorError::MosaicErr(format!("init_evaluator_deposit: {e:?}")))?;
        info!(?graph_idx, %game_index, %watchtower_idx, "mosaic init_evaluator_deposit ok");
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

/// Kicks off mosaic adaptor verification by calling `init_garbler_deposit` as the POV watchtower.
///
/// Before initializing, cross-checks `fault_pubkey` from the received graph data against the
/// locally-known fault pubkey for the garbler-side tableset (where the graph owner is the
/// evaluator peer). A mismatch means the graph data was not produced from the same tableset
/// this node has set up, which makes adaptor verification impossible.
///
/// The graph owner is the evaluator in this setup, so `graph_idx.operator` is the remote peer.
/// Verification itself runs asynchronously on mosaic; completion is signaled later via
/// [`MosaicEvent::AdaptorsVerified`](strata_mosaic_client_api::MosaicEvent::AdaptorsVerified)
pub(super) async fn verify_adaptors(
    output_handles: &OutputHandles,
    graph_idx: GraphIdx,
    game_index: GameIndex,
    watchtower_idx: OperatorIdx,
    sighashes: &[Message],
    adaptor_pubkey: XOnlyPublicKey,
    fault_pubkey: XOnlyPublicKey,
) -> Result<(), ExecutorError> {
    info!(
        ?graph_idx,
        %game_index,
        %watchtower_idx,
        num_sighashes = sighashes.len(),
        "verifying adaptor signatures"
    );

    let local_fault_pubkey = output_handles
        .mosaic_client
        .get_fault_pubkey(graph_idx.operator, Role::Garbler)
        .await
        .map_err(|e| ExecutorError::MosaicErr(format!("get_fault_pubkey: {e:?}")))?
        .ok_or_else(|| {
            ExecutorError::MosaicErr(format!(
                "local fault pubkey missing for owner={}, deposit={}",
                graph_idx.operator, graph_idx.deposit
            ))
        })?;
    if local_fault_pubkey != fault_pubkey {
        return Err(ExecutorError::MosaicErr(format!(
            "fault pubkey mismatch for graph {graph_idx:?}: graph_data has {fault_pubkey}, \
             local mosaic reports {local_fault_pubkey}"
        )));
    }

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

    output_handles
        .mosaic_client
        .init_garbler_deposit(
            graph_idx.operator,
            game_index,
            deposit_sighashes,
            adaptor_pubkey,
        )
        .await
        .map_err(|e| ExecutorError::MosaicErr(format!("init_garbler_deposit: {e:?}")))?;

    info!(
        ?graph_idx,
        %game_index,
        %watchtower_idx,
        "mosaic init_garbler_deposit ok; awaiting AdaptorsVerified event"
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
    sighashes: &[Message],
    ordered_pubkeys: &[XOnlyPublicKey],
) -> Result<(), ExecutorError> {
    info!(?graph_idx, "publishing graph nonces");

    let musig_signer = output_handles.s2_client.musig2_signer();
    let ordered_pubkeys = ordered_pubkeys.to_vec();

    // Generate nonces for each inpoint concurrently
    let nonce_futures = graph_inpoints
        .iter()
        .zip(graph_tweaks.iter())
        .zip(sighashes.iter())
        .map(|((inpoint, tweak), sighash)| {
            let params = Musig2Params {
                ordered_pubkeys: ordered_pubkeys.clone(),
                tweak: *tweak,
                sighash: *sighash.as_ref(),
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
    stake_outpoint: OutPoint,
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

    info!(
        ?graph_idx,
        %stake_outpoint,
        "ensuring stake outpoint is unspent before publishing partials"
    );
    if !is_outpoint_unspent(&output_handles.bitcoind_rpc_client, &stake_outpoint)
        .await
        .map_err(ExecutorError::BitcoinRpcErr)?
    {
        warn!(
            ?graph_idx,
            %stake_outpoint,
            "stake outpoint already spent, aborting partial sig generation"
        );
        return Err(ExecutorError::StakeOutPointAlreadySpent(stake_outpoint));
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
                sighash: *sighash.as_ref(),
            };
            musig_signer
                .get_our_partial_sig(params, agg_nonce.clone())
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
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    claim_tx: &ClaimTx,
) -> Result<(), ExecutorError> {
    let unsigned_claim_tx = claim_tx.as_ref().clone();
    let claim_txid = unsigned_claim_tx.compute_txid();
    info!(
        %claim_txid,
        "signing claim transaction"
    );

    let claim_prevout: TxOut = {
        let wallet = output_handles.wallet.read().await;
        wallet
            .reserved_utxos_with_value(cfg.claim_funding_utxo_value)
            .into_iter()
            .find(|utxo| utxo.outpoint == claim_tx.as_ref().input[0].previous_output)
            .expect("claim funding outpoint not found in wallet")
            .into()
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
        // This means we should not use the general wallet. `reserved_signer` is currently used
        // as a placeholder non-general wallet, so the funding outputs should also be generated
        // from the `reserved_signer` wallet.
        let signature = output_handles
            .s2_client
            .reserved_wallet_signer()
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

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, io, sync::Arc, time::Duration};

    use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as CoreRpcClient};
    use bitcoin::{
        Amount, FeeRate, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey,
        hashes::Hash,
        secp256k1::{Keypair, SECP256K1, SecretKey},
    };
    use corepc_node::{Conf, Node};
    use operator_wallet::{
        FundedPsbt, GeneralWallet, OperatorWallet, OperatorWalletConfig, UtxoInfo, sync::Backend,
    };
    use strata_bridge_test_utils::bridge_fixtures::test_operator_table;

    use super::{reconcile_claim_funding_leases_after_driver_failure, watchtower_idxs};

    #[derive(Debug)]
    struct ReconciliationGeneralWallet {
        live_utxos: Vec<UtxoInfo>,
        sync_fails: bool,
    }

    impl GeneralWallet for ReconciliationGeneralWallet {
        type Error = io::Error;

        async fn sync(&mut self) -> Result<(), Self::Error> {
            if self.sync_fails {
                Err(io::Error::other("test sync failure"))
            } else {
                Ok(())
            }
        }

        fn script_pubkey(&self) -> ScriptBuf {
            ScriptBuf::new()
        }

        fn list_utxos(&self) -> Vec<UtxoInfo> {
            self.live_utxos.clone()
        }

        async fn fund_v3_transaction(
            &mut self,
            _outputs: Vec<TxOut>,
            _explicit_inputs: Option<&[OutPoint]>,
            _fee_rate: FeeRate,
            _exclude: &[OutPoint],
        ) -> Result<FundedPsbt, Self::Error> {
            unreachable!("reconciliation tests do not fund transactions")
        }

        async fn build_cpfp_child(
            &mut self,
            _parent: &Transaction,
            _anchor_vout: u32,
            _target_pkg_fee_rate: FeeRate,
            _exclude: &[OutPoint],
        ) -> Result<FundedPsbt, Self::Error> {
            unreachable!("reconciliation tests do not build CPFP transactions")
        }
    }

    fn xonly_pubkey(byte: u8) -> XOnlyPublicKey {
        let secret_key = SecretKey::from_slice(&[byte; 32]).expect("valid secret key");
        Keypair::from_secret_key(SECP256K1, &secret_key)
            .x_only_public_key()
            .0
    }

    fn core_rpc_client(bitcoind: &Node) -> CoreRpcClient {
        let auth = Auth::CookieFile(bitcoind.params.cookie_file.clone());
        CoreRpcClient::new(bitcoind.rpc_url().as_str(), auth).expect("core rpc client")
    }

    fn reconciliation_wallet(
        bitcoind: &Node,
        live_utxos: Vec<UtxoInfo>,
        sync_fails: bool,
        initial_leases: BTreeSet<OutPoint>,
    ) -> OperatorWallet<ReconciliationGeneralWallet> {
        let general = ReconciliationGeneralWallet {
            live_utxos,
            sync_fails,
        };
        let config = OperatorWalletConfig::new(Amount::from_sat(330), Network::Regtest)
            .with_sync_policy(0, 1, Duration::ZERO);

        OperatorWallet::new(
            general,
            xonly_pubkey(42),
            config,
            Backend::BitcoinCore(Arc::new(core_rpc_client(bitcoind))),
            initial_leases,
        )
    }

    fn test_utxo(outpoint: OutPoint) -> UtxoInfo {
        UtxoInfo {
            outpoint,
            amount: Amount::ONE_BTC,
            confirmations: 1,
            script_pubkey: ScriptBuf::new(),
        }
    }

    #[test]
    fn watchtower_order_uses_supplied_operator_table_snapshot() {
        let historical_table = test_operator_table(3, 0);
        let later_table = test_operator_table(4, 0);

        let historical_watchtowers: Vec<_> = watchtower_idxs(&historical_table, 0).collect();
        let later_watchtowers: Vec<_> = watchtower_idxs(&later_table, 0).collect();

        assert_eq!(historical_watchtowers, vec![1, 2]);
        assert_eq!(later_watchtowers, vec![1, 2, 3]);
    }

    #[tokio::test]
    async fn reconciliation_prunes_spent_inputs_and_releases_live_inputs() {
        let bitcoind = Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind starts");
        let spent = OutPoint {
            txid: Txid::from_slice(&[1; 32]).expect("valid txid"),
            vout: 0,
        };
        let live = OutPoint {
            txid: Txid::from_slice(&[2; 32]).expect("valid txid"),
            vout: 0,
        };
        let mut wallet = reconciliation_wallet(
            &bitcoind,
            vec![test_utxo(live)],
            false,
            BTreeSet::from([spent, live]),
        );

        reconcile_claim_funding_leases_after_driver_failure(&mut wallet, &[spent, live]).await;

        assert!(
            wallet.leased_outpoints().is_empty(),
            "sync should prune the spent input and reconciliation should release the live input"
        );
    }

    #[tokio::test]
    async fn reconciliation_retains_input_leases_when_sync_fails() {
        let bitcoind = Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind starts");
        let input = OutPoint {
            txid: Txid::from_slice(&[3; 32]).expect("valid txid"),
            vout: 0,
        };
        let mut wallet = reconciliation_wallet(
            &bitcoind,
            vec![test_utxo(input)],
            true,
            BTreeSet::from([input]),
        );

        reconcile_claim_funding_leases_after_driver_failure(&mut wallet, &[input]).await;

        assert_eq!(wallet.leased_outpoints(), &BTreeSet::from([input]));
    }
}
