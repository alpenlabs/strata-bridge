//! Executors for uncontested payout graph duties.

use algebra::predicate;
use bitcoin::{
    Amount, OutPoint, TapSighashType, TxOut, Txid, XOnlyPublicKey,
    sighash::{Prevouts, SighashCache},
};
use bitcoind_async_client::{Client as BitcoinClient, traits::Reader};
use btc_tracker::{cpfp::DeadlineClass, event::TxStatus};
use futures::{FutureExt, future::try_join_all};
use musig2::{AggNonce, PartialSignature, PubNonce, secp256k1::Message};
use operator_wallet::{GeneralUtxoPolicy, Lease, LeaseOwner, OperatorWallet, WalletStore};
use secret_service_proto::v2::traits::{Musig2Params, Musig2Signer, SchnorrSigner, SecretService};
use strata_bridge_connectors::{Connector, ParentTx};
use strata_bridge_db::{
    traits::BridgeDb,
    types::{ClaimFundingReservation, FundingAssignment},
};
use strata_bridge_p2p_types::{GraphData, XOnlyPubKey};
use strata_bridge_primitives::{
    operator_table::OperatorTable,
    scripts::taproot::{TaprootTweak, TaprootWitness, create_message_hash},
    types::{GameIndex, GraphIdx, OperatorIdx},
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
use tracing::{info, warn};

use crate::{
    chain::{self, CpfpKind, is_outpoint_unspent, is_txid_onchain, publish_signed_transaction},
    config::ExecutionConfig,
    errors::ExecutorError,
    fees::funding_fee_rate,
    output_handles::OutputHandles,
};

pub(super) async fn generate_graph_data(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    ctx: &GraphSMCtx,
) -> Result<(), ExecutorError> {
    let graph_idx = ctx.graph_idx();
    let deposit_outpoint = ctx.deposit_outpoint();
    let stake_outpoint = ctx.stake_outpoint();
    let operator_table = ctx.operator_table();
    info!(
        ?graph_idx,
        %deposit_outpoint,
        %stake_outpoint,
        "generating graph data"
    );

    let game_index = GameIndex::try_from(graph_idx.deposit)
        .expect("deposit index does not overflow when mapped to game index");

    let funding_outpoint = ensure_claim_funding_outpoint(cfg, output_handles, ctx).await?;
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
    let game_graph = generate_game_graph(&cfg.graph_sm_cfg, ctx, &deposit_params);
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
        .await?;
    info!(?graph_idx, "broadcasted graph data");

    Ok(())
}

fn invalid_mosaic_key(err: bitcoin::secp256k1::Error) -> ExecutorError {
    ExecutorError::MosaicErr(format!("invalid mosaic pubkey: {err:?}"))
}

// Selection must not use cached confirmations when either wallet fails to sync.
async fn reserve_synced_claim_funding<P: WalletStore>(
    wallet: &mut OperatorWallet<P>,
    value: Amount,
    bury_depth: u32,
) -> Result<Option<(OutPoint, Lease)>, ExecutorError> {
    wallet.sync().await.map_err(|e| {
        ExecutorError::WalletErr(format!(
            "wallet sync failed before selecting claim funding: {e:?}"
        ))
    })?;
    Ok(wallet.reserve_settled(value, bury_depth))
}

/// Holds the claim-funding outpoint of a stored reservation.
///
/// The row keeps the outpoint across restarts, and startup rehydration holds it. This covers a
/// row that was written after startup read the funds, so the outpoint cannot go to another graph.
/// The hold is committed even when an uncommitted lease of the same duty holds the outpoint, since
/// that lease drops with the duty. An outpoint that a committed lease holds takes no second record,
/// so a repeated duty adds nothing.
fn hold_stored_claim_funding<P: WalletStore>(wallet: &OperatorWallet<P>, outpoint: OutPoint) {
    wallet.lease_committed(vec![outpoint], LeaseOwner::ClaimFunding);
}

/// Returns the outpoint of `reservation` if it holds exactly `value`, so that a reservation of
/// another amount is never spent for this graph's claim.
///
/// A mismatch fails on every retry, and the row stays. Unlike a stake reservation, this row can
/// back graph data that peers hold, so a replacement outpoint does not recover the graph. An
/// operator edits the row.
fn check_claim_funding(
    reservation: &ClaimFundingReservation,
    value: Amount,
) -> Result<OutPoint, ExecutorError> {
    if reservation.txout.value == value {
        Ok(reservation.outpoint)
    } else {
        Err(ExecutorError::ClaimFundingMismatch {
            outpoint: reservation.outpoint,
            found: reservation.txout.value,
            expected: value,
        })
    }
}

/// Returns the claim-funding outpoint for the graph of `ctx`, fetching it from the wallet and
/// caching to disk when not already saved. An empty pool starts a refill, and the duty takes one
/// of the refill's outputs once the refill transaction is in the node's mempool.
///
/// The output is sized for the graph's own membership, and a cached reservation is reused only
/// if it holds exactly that amount.
async fn ensure_claim_funding_outpoint(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    ctx: &GraphSMCtx,
) -> Result<OutPoint, ExecutorError> {
    let covenant = ctx.covenant;
    let graph_idx = ctx.graph_idx();
    let value = ctx.claim_funding_value(&cfg.graph_sm_cfg);
    if let Ok(Some(reservation)) = output_handles
        .db
        .get_claim_funding_reservation(covenant, graph_idx)
        .await
    {
        info!(
            ?graph_idx,
            funding_outpoint = ?reservation.outpoint,
            "reusing cached funding outpoint"
        );
        let outpoint = check_claim_funding(&reservation, value)?;
        hold_stored_claim_funding(&*output_handles.wallet.read().await, outpoint);
        return Ok(outpoint);
    }

    info!(?graph_idx, %value, "fetching funding outpoint from wallet");
    let reserved = {
        let mut wallet = output_handles.wallet.write().await;
        reserve_synced_claim_funding(&mut wallet, value, cfg.bury_depth).await?
    };
    let (outpoint, funding_lease) = match reserved {
        Some(reserved) => reserved,
        None => refill_claim_funding(cfg, output_handles, value).await?,
    };
    let reservation = ClaimFundingReservation {
        outpoint,
        txout: TxOut {
            value,
            script_pubkey: output_handles.wallet.read().await.reserved_script_pubkey(),
        },
    };

    let assignment = output_handles
        .db
        .get_or_set_claim_funding_reservation(covenant, graph_idx, reservation)
        .await;

    // The database now owns the claim-funding outpoint of this graph, so the reservation
    // outlives this duty. `commit` keeps it held after `funding_lease` drops.
    let assigned_outpoint = match assignment {
        Ok(FundingAssignment::Created(reservation)) => {
            info!(?graph_idx, outpoint = %reservation.outpoint, "saved funding outpoint to disk");
            funding_lease.commit();
            reservation.outpoint
        }
        Ok(FundingAssignment::Existing(reservation)) => {
            info!(
                ?graph_idx,
                outpoint = %reservation.outpoint,
                "using existing funding outpoint saved by another duty"
            );
            let outpoint = check_claim_funding(&reservation, value)?;
            // The row owns this outpoint, whatever `funding_lease` holds. The candidate drops.
            hold_stored_claim_funding(&*output_handles.wallet.read().await, outpoint);
            outpoint
        }
        Err(err) => return Err(err.into()),
    };

    Ok(assigned_outpoint)
}

/// Tops up the claim-funding pool of `value` and takes a lease on one of the new outputs, or on an
/// output that settled while this duty waited for the refill lock.
///
/// The refill spends buried general-wallet inputs at the rate of [`funding_fee_rate`]. Because its
/// inputs are buried, a duty can reserve one of its outputs as soon as the refill transaction is in
/// the node's mempool; the claim itself publishes once the refill is in a block (see
/// `funding_confirmed`). The batch is the whole pool size: the reservation before the refill found
/// no free settled member.
///
/// One refill runs at a time. The refill lock is held across signing and the wait for the mempool,
/// so a second duty that finds the pool empty waits for this refill and then takes one of its
/// outputs.
async fn refill_claim_funding(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    value: Amount,
) -> Result<(OutPoint, Lease), ExecutorError> {
    let _refill = output_handles.claim_funding_refill.lock().await;
    // Read before the wallet guard, because this can wait for the source for up to
    // `QUOTE_READ_TIMEOUT`. A reservation from the pool does not use the rate, so its error applies
    // only when this path builds a refill.
    let fee_rate = funding_fee_rate(&cfg.fee_quotes, cfg.maximum_fee_rate).await;
    let mut wallet = output_handles.wallet.write().await;
    if let Some(reserved) = reserve_synced_claim_funding(&mut wallet, value, cfg.bury_depth).await?
    {
        return Ok(reserved);
    }

    warn!("could not acquire claim funding utxo. attempting refill...");
    let fee_rate = fee_rate?;
    // The wallet stays denomination-agnostic; the batch is sized here.
    //
    // `refill` holds the general-wallet inputs of the refill transaction. A path that ends before
    // the transaction reaches a mempool drops it, which returns those inputs to the pool. A path
    // that cannot tell drops it only after a fresh sync makes the wallet view authoritative.
    let refill = wallet
        .create_reserved_utxos(
            fee_rate,
            value,
            cfg.funding_uxto_pool_size,
            GeneralUtxoPolicy::BuriedOnly {
                bury_depth: cfg.bury_depth,
            },
            LeaseOwner::ClaimFundingRefill,
        )
        .map_err(|e| ExecutorError::WalletErr(format!("refill failed: {e}")))?;
    // The lease holds the inputs from here, so signing and the wait for the mempool hold no wallet
    // guard.
    drop(wallet);
    let (refill_psbt, refill_lease) = refill.into_parts();
    let tx = chain::sign_general_inputs(
        output_handles,
        &refill_psbt.unsigned_tx,
        &(0..refill_psbt.unsigned_tx.input.len()).collect::<Vec<_>>(),
        &chain::psbt_prevouts(&refill_psbt),
    )
    .await?;
    let txid = tx.compute_txid();
    let refill_fee = refill_psbt
        .fee()
        .map_err(|e| ExecutorError::WalletErr(format!("refill psbt fee: {e:?}")))?;
    info!(%txid, "submitting claim funding tx to the tx driver");
    // The duty continues once the refill is in the mempool. A child of the change output, which
    // the planner always leaves, bumps the refill until its burial.
    if let Err(err) = chain::publish_signed_transaction_until(
        output_handles,
        &tx,
        "claim funding refill",
        CpfpKind::InferGeneralPayout {
            parent_fee: chain::ParentFee::Exact(refill_fee),
            deadline: DeadlineClass::NoDeadline,
        },
        predicate::eq(TxStatus::Mempool),
    )
    .await
    {
        let mut wallet = output_handles.wallet.write().await;
        if let Err(sync_err) = chain::release_after_sync(&mut wallet, refill_lease).await {
            warn!(
                ?sync_err,
                "wallet sync failed after a refill driver failure"
            );
        }
        return Err(err);
    }
    info!(%txid, "claim funding tx detected in mempool");
    // The lease on the refill's inputs commits. The refill spends them, so the lease costs nothing
    // while it lives; if the node evicts the refill, the lease is what keeps another duty from
    // spending an input and killing the refill, whose outputs stored rows name. The sync prune
    // frees the inputs once the refill is buried.
    refill_lease.commit();
    let mut wallet = output_handles.wallet.write().await;
    wallet
        .sync()
        .await
        .map_err(|e| ExecutorError::WalletErr(format!("wallet sync failed after refill: {e:?}")))?;
    // The refilled pool members are unconfirmed, so they are only visible while the funding
    // transaction is in the node's mempool. An eviction between the tx-driver's check and this
    // sync leaves nothing to reserve, and the duty retries. The committed lease keeps the inputs
    // of the evicted refill held until a restart.
    wallet
        .reserve_settled(value, cfg.bury_depth)
        .ok_or_else(|| {
            ExecutorError::WalletErr("no claim-funding utxo available after refill".to_string())
        })
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
        .await?;

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
        .await?;

    info!(?graph_idx, "graph partials published");
    Ok(())
}

/// Returns the output that a claim spends.
///
/// The reserved wallet lists the output while it is unspent. Once the claim is in a mempool, the
/// wallet no longer offers the output, and a retry of this duty still signs: the node then
/// supplies the output from the funding transaction.
async fn claim_prevout(
    output_handles: &OutputHandles,
    claim_funding_outpoint: OutPoint,
) -> Result<TxOut, ExecutorError> {
    if let Some(utxo) = output_handles
        .wallet
        .read()
        .await
        .reserved_utxo(claim_funding_outpoint)
    {
        return Ok(TxOut::from(utxo));
    }
    let funding_tx = output_handles
        .bitcoind_rpc_client
        .get_raw_transaction_verbosity_zero(&claim_funding_outpoint.txid)
        .await
        .map_err(|e| {
            warn!(%claim_funding_outpoint, ?e, "the claim funding output is not in the wallet");
            ExecutorError::ClaimFundingOutPointMissing(claim_funding_outpoint)
        })?
        .0;
    funding_tx
        .output
        .get(claim_funding_outpoint.vout as usize)
        .cloned()
        .ok_or(ExecutorError::ClaimFundingOutPointMissing(
            claim_funding_outpoint,
        ))
}

/// Whether a block holds the transaction that creates `claim_funding_outpoint`.
///
/// A claim is a v3 transaction, and an unconfirmed v3 transaction takes one child at most, so a
/// claim on an unconfirmed refill would take the only child of the refill. A transaction the node
/// does not know fails as a missing outpoint.
async fn funding_confirmed(
    bitcoind_rpc_client: &BitcoinClient,
    claim_funding_outpoint: OutPoint,
) -> Result<bool, ExecutorError> {
    match chain::tx_confirmations(bitcoind_rpc_client, &claim_funding_outpoint.txid).await {
        Ok(Some(depth)) => Ok(depth > 0),
        Ok(None) => Err(ExecutorError::ClaimFundingOutPointMissing(
            claim_funding_outpoint,
        )),
        Err(e) => Err(ExecutorError::BitcoinRpcErr(e)),
    }
}

/// [`funding_confirmed`], and a re-drive of a refill that sits in the mempool.
///
/// A refill that an earlier process broadcast has no driver record and no lease on its inputs. This
/// holds its inputs again and hands it back to the driver with its CPFP path. The claim still waits
/// for the confirmation, so the answer stands.
async fn funding_confirmed_or_drive(
    output_handles: &OutputHandles,
    claim_funding_outpoint: OutPoint,
) -> Result<bool, ExecutorError> {
    let client = &output_handles.bitcoind_rpc_client;
    let confirmed = funding_confirmed(client, claim_funding_outpoint).await?;
    if !confirmed {
        let refill = client
            .get_raw_transaction_verbosity_zero(&claim_funding_outpoint.txid)
            .await?
            .0;
        info!(txid = %refill.compute_txid(), "driving the unconfirmed claim funding refill");
        // The refill's general-wallet inputs are held again, so another duty cannot spend them if
        // the refill leaves the mempool.
        let inputs = refill
            .input
            .iter()
            .map(|input| input.previous_output)
            .collect();
        output_handles
            .wallet
            .read()
            .await
            .lease_committed(inputs, LeaseOwner::ClaimFundingRefill);
        chain::publish_signed_transaction_until(
            output_handles,
            &refill,
            "claim funding refill",
            CpfpKind::InferGeneralPayout {
                parent_fee: chain::ParentFee::FromPrevouts,
                deadline: DeadlineClass::NoDeadline,
            },
            predicate::eq(TxStatus::Mempool),
        )
        .await?;
    }
    Ok(confirmed)
}

/// Publishes the claim transaction to Bitcoin.
///
/// The prevout comes from the reserved wallet, or from the node once a transaction spends the
/// output and the wallet stops listing it: a retry after the claim reached a mempool must still
/// sign. A claim waits for its funding transaction to confirm. Until then the duty returns without
/// publishing, and the retry tick runs it again.
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

    let claim_funding_outpoint = unsigned_claim_tx.input[0].previous_output;
    let claim_prevout = claim_prevout(output_handles, claim_funding_outpoint).await?;
    if !funding_confirmed_or_drive(output_handles, claim_funding_outpoint).await? {
        info!(
            %claim_txid,
            %claim_funding_outpoint,
            "waiting for the claim funding tx to confirm"
        );
        return Ok(());
    }

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
        output_handles,
        &signed_claim_tx,
        "claim",
        CpfpKind::AnchorAt {
            anchor_vout: ClaimTx::CPFP_VOUT,
            anchor_key: claim_tx.cpfp_connector().internal_key(),
            parent_fee: chain::ParentFee::FromPrevouts,
            deadline: DeadlineClass::NoDeadline,
        },
    )
    .await
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, slice, sync::Arc, time::Duration};

    use bdk_bitcoind_rpc::bitcoincore_rpc::{Auth, Client as CoreRpcClient};
    use bitcoin::{
        Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Sequence, TapSighashType,
        Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
        absolute::LockTime,
        hashes::Hash,
        key::TapTweak,
        secp256k1::{Keypair, Message, SECP256K1, SecretKey},
        sighash::{Prevouts, SighashCache},
        transaction::{InputWeightPrediction, Version},
    };
    use bitcoind_async_client::{Auth as RpcAuth, Client as BitcoinClient};
    use corepc_node::{Conf, Node};
    use operator_wallet::{
        FundingInput, GeneralCustody, LeaseOwner, OperatorWallet, OperatorWalletConfig,
        sync::Backend, test_utils::MemoryStore,
    };
    use strata_bridge_db::types::ClaimFundingReservation;
    use strata_bridge_test_utils::bridge_fixtures::test_operator_table;

    use super::{
        ExecutorError, chain, check_claim_funding, funding_confirmed, hold_stored_claim_funding,
        reserve_synced_claim_funding, watchtower_idxs,
    };

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

    /// A wallet over fresh in-memory stores. A failed sync fails at once, with no retry.
    async fn test_wallet(bitcoind: &Node) -> OperatorWallet<MemoryStore> {
        OperatorWallet::load_or_create(
            GeneralCustody::SecretService {
                general_key: xonly_pubkey(41),
                store: MemoryStore::new(),
            },
            xonly_pubkey(42),
            OperatorWalletConfig::new(0, Network::Regtest).with_sync_policy(0, 1, Duration::ZERO),
            Backend::BitcoinCore(Arc::new(core_rpc_client(bitcoind))),
            MemoryStore::new(),
            None,
            BTreeSet::new(),
        )
        .await
        .expect("the wallet initialises against empty stores")
    }

    /// Pays one output of each of `values` to the general wallet from the node's wallet, confirms
    /// them, and syncs. The node's wallet needs mature funds.
    async fn fund_general(
        bitcoind: &Node,
        wallet: &mut OperatorWallet<MemoryStore>,
        values: &[Amount],
    ) {
        let address = Address::from_script(&wallet.general().script_pubkey(), Network::Regtest)
            .expect("general address");
        for value in values {
            bitcoind
                .client
                .send_to_address(&address, *value)
                .expect("fund general wallet");
        }
        let miner = bitcoind.client.new_address().expect("miner");
        bitcoind
            .client
            .generate_to_address(1, &miner)
            .expect("confirm funding");
        wallet.sync().await.expect("wallet syncs");
    }

    /// Gives the node's wallet mature funds.
    fn mature_node_funds(bitcoind: &Node) {
        let miner = bitcoind.client.new_address().expect("miner");
        bitcoind
            .client
            .generate_to_address(101, &miner)
            .expect("mature funds");
    }

    #[tokio::test]
    async fn claim_funding_rejects_cached_utxo_after_sync_failure() {
        let bitcoind = Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind starts");
        let mut wallet = test_wallet(&bitcoind).await;
        let miner = bitcoind.client.new_address().expect("miner");
        bitcoind
            .client
            .generate_to_address(101, &miner)
            .expect("mature funds");
        let address = Address::from_script(&wallet.reserved_script_pubkey(), Network::Regtest)
            .expect("reserved address");
        let value = Amount::from_sat(100_000);
        bitcoind
            .client
            .send_to_address(&address, value)
            .expect("fund reserved wallet");
        bitcoind
            .client
            .generate_to_address(3, &miner)
            .expect("bury funding");
        wallet.sync().await.expect("cache buried output");
        assert_eq!(
            wallet.reserved_utxos_with_value(value).len(),
            1,
            "the synced wallet lists the buried output"
        );

        drop(bitcoind);
        let result = reserve_synced_claim_funding(&mut wallet, value, 2).await;
        assert!(matches!(result, Err(ExecutorError::WalletErr(_))));
        assert!(
            wallet.leased_outpoints().is_empty(),
            "stale funding must not be reserved"
        );
    }

    /// A retried database write can return the reservation this duty wrote itself. The outpoint
    /// must stay held after the duty's own lease on it drops.
    #[tokio::test]
    async fn a_stored_outpoint_that_the_duty_itself_leased_stays_held() {
        let bitcoind = Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind starts");
        let mut wallet = test_wallet(&bitcoind).await;
        mature_node_funds(&bitcoind);
        let address = Address::from_script(&wallet.reserved_script_pubkey(), Network::Regtest)
            .expect("reserved address");
        let value = Amount::from_sat(100_000);
        bitcoind
            .client
            .send_to_address(&address, value)
            .expect("fund reserved wallet");
        let miner = bitcoind.client.new_address().expect("miner");
        bitcoind
            .client
            .generate_to_address(3, &miner)
            .expect("bury funding");
        wallet.sync().await.expect("sync");
        let (outpoint, candidate) = wallet
            .reserve_settled(value, 2)
            .expect("a settled output of the graph value");

        hold_stored_claim_funding(&wallet, outpoint);
        drop(candidate);
        assert!(
            wallet.leased_outpoints().contains(&outpoint),
            "the stored reservation holds the outpoint after the candidate lease drops"
        );
    }

    #[tokio::test]
    async fn claim_funding_selects_only_the_graph_denomination() {
        let bitcoind = Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind starts");
        let mut wallet = test_wallet(&bitcoind).await;
        let miner = bitcoind.client.new_address().expect("miner");
        bitcoind
            .client
            .generate_to_address(101, &miner)
            .expect("mature funds");
        let address = Address::from_script(&wallet.reserved_script_pubkey(), Network::Regtest)
            .expect("reserved address");
        let smaller = Amount::from_sat(100_000);
        let larger = Amount::from_sat(150_000);
        for value in [smaller, larger] {
            bitcoind
                .client
                .send_to_address(&address, value)
                .expect("fund reserved wallet");
        }
        bitcoind
            .client
            .generate_to_address(3, &miner)
            .expect("bury funding");

        let first = reserve_synced_claim_funding(&mut wallet, smaller, 2)
            .await
            .expect("wallet syncs")
            .expect("a settled output of the smaller amount exists");
        let second = reserve_synced_claim_funding(&mut wallet, larger, 2)
            .await
            .expect("wallet syncs")
            .expect("a settled output of the larger amount exists");
        assert_eq!(
            [
                wallet.reserved_utxos_with_value(smaller)[0].outpoint,
                wallet.reserved_utxos_with_value(larger)[0].outpoint,
            ],
            [first.0, second.0],
            "each graph must be funded at its own amount"
        );

        let exhausted = reserve_synced_claim_funding(&mut wallet, larger, 2)
            .await
            .expect("wallet syncs");
        assert!(
            exhausted.is_none(),
            "no other output of the larger amount remains"
        );
        assert!(
            wallet.leased_outpoints().contains(&first.0)
                && wallet.leased_outpoints().contains(&second.0),
            "an exhausted pool must leave reservations of every amount in place"
        );
    }

    /// An output paid into the reserved wallet from outside funds no claim until it is buried.
    #[tokio::test]
    async fn claim_funding_waits_for_burial_of_an_external_output() {
        let bitcoind = Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind starts");
        let mut wallet = test_wallet(&bitcoind).await;
        let miner = bitcoind.client.new_address().expect("miner");
        bitcoind
            .client
            .generate_to_address(101, &miner)
            .expect("mature funds");
        let address = Address::from_script(&wallet.reserved_script_pubkey(), Network::Regtest)
            .expect("reserved address");
        let value = Amount::from_sat(100_000);
        let bury_depth = 2;
        bitcoind
            .client
            .send_to_address(&address, value)
            .expect("fund reserved wallet");

        for block in 0..=bury_depth {
            let reserved = reserve_synced_claim_funding(&mut wallet, value, bury_depth)
                .await
                .expect("wallet syncs");
            assert!(
                reserved.is_none(),
                "an output {block} blocks deep is not settled"
            );
            bitcoind
                .client
                .generate_to_address(1, &miner)
                .expect("mine a block");
        }

        let reserved = reserve_synced_claim_funding(&mut wallet, value, bury_depth)
            .await
            .expect("wallet syncs");
        assert!(reserved.is_some(), "a buried output is settled");
    }

    /// A refill that left the mempool before the sync is one that the wallet never saw, so its
    /// inputs read as unspent and return to selection.
    #[tokio::test]
    async fn a_refill_that_no_mempool_holds_at_the_sync_returns_its_inputs() {
        let bitcoind = Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind starts");
        mature_node_funds(&bitcoind);
        let mut wallet = test_wallet(&bitcoind).await;
        fund_general(&bitcoind, &mut wallet, &[Amount::from_sat(100_000)]).await;
        let (_, refill_lease) = wallet
            .select_general_utxo(LeaseOwner::ClaimFundingRefill, Amount::ONE_SAT)
            .expect("the input is selectable");

        chain::release_after_sync(&mut wallet, refill_lease)
            .await
            .expect("sync succeeds");

        assert!(
            wallet.leased_outpoints().is_empty(),
            "the inputs of a refill that no mempool holds must not stay held"
        );
        assert!(
            wallet
                .select_general_utxo(LeaseOwner::ClaimFundingRefill, Amount::ONE_SAT)
                .is_some(),
            "the next refill can spend them again"
        );
    }

    /// A key-path spend of `input` by the general key of [`test_wallet`], to a foreign script.
    fn spend_general_input(input: &FundingInput) -> Transaction {
        let mut tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: input.outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: input.txout.value - Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new_p2tr(SECP256K1, xonly_pubkey(43), None),
            }],
        };
        let sighash = SighashCache::new(&tx)
            .taproot_key_spend_signature_hash(
                0,
                &Prevouts::All(slice::from_ref(&input.txout)),
                TapSighashType::Default,
            )
            .expect("sighash");
        let keypair = Keypair::from_secret_key(
            SECP256K1,
            &SecretKey::from_slice(&[41; 32]).expect("valid secret key"),
        );
        let tweaked = keypair.tap_tweak(SECP256K1, None).to_keypair();
        let signature = SECP256K1.sign_schnorr_no_aux_rand(&Message::from(sighash), &tweaked);
        tx.input[0].witness.push(signature.as_ref());
        tx
    }

    /// A publish can fail after its transaction reached a mempool. The sync then shows the input
    /// as spent, so the release leaves it out of selection.
    #[tokio::test]
    async fn a_failed_publish_that_reached_a_mempool_keeps_its_input_out_of_selection() {
        let bitcoind = Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind starts");
        mature_node_funds(&bitcoind);
        let mut wallet = test_wallet(&bitcoind).await;
        fund_general(&bitcoind, &mut wallet, &[Amount::from_sat(100_000)]).await;
        let (input, lease) = wallet
            .select_general_utxo(LeaseOwner::ClaimFundingRefill, Amount::ONE_SAT)
            .expect("the input is selectable");
        bitcoind
            .client
            .send_raw_transaction(&spend_general_input(&input))
            .expect("the spend reaches the mempool");

        chain::release_after_sync(&mut wallet, lease)
            .await
            .expect("sync succeeds");

        assert!(
            wallet
                .select_general_utxo(LeaseOwner::ClaimFundingRefill, Amount::ONE_SAT)
                .is_none(),
            "an input that a mempool transaction spends is not offered again"
        );
    }

    /// A claim on a refill that is not confirmed waits, a claim on a refill the node does not know
    /// is missing its outpoint, and a claim whose funding output is spent must still pass, because
    /// a retry signs after the claim reached a mempool.
    #[tokio::test]
    async fn a_claim_needs_a_confirmed_funding_tx_and_survives_its_spend() {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let bitcoind = Node::with_conf("bitcoind", &conf).expect("bitcoind starts");
        let cookie = bitcoind
            .params
            .get_cookie_values()
            .expect("cookie file reads")
            .expect("cookie file holds credentials");
        let client = BitcoinClient::new(
            bitcoind.rpc_url(),
            RpcAuth::UserPass(cookie.user, cookie.password),
            None,
            None,
            None,
        )
        .expect("rpc client");
        let miner = bitcoind.client.new_address().expect("miner");
        bitcoind
            .client
            .generate_to_address(101, &miner)
            .expect("mature funds");
        let address = bitcoind.client.new_address().expect("address");
        let funding = bitcoind
            .client
            .send_to_address(&address, Amount::from_sat(100_000))
            .expect("funding")
            .txid()
            .expect("txid");
        let outpoint = OutPoint::new(funding, 0);

        assert!(
            matches!(funding_confirmed(&client, outpoint).await, Ok(false)),
            "a funding tx in the mempool is not confirmed yet"
        );
        assert!(
            matches!(
                funding_confirmed(&client, OutPoint::new(Txid::all_zeros(), 0)).await,
                Err(ExecutorError::ClaimFundingOutPointMissing(_))
            ),
            "a funding tx the node does not know is missing"
        );

        bitcoind
            .client
            .generate_to_address(1, &miner)
            .expect("confirm");
        assert!(
            funding_confirmed(&client, outpoint)
                .await
                .expect("a confirmed funding tx reads"),
            "a confirmed funding tx passes"
        );

        bitcoind
            .client
            .call::<serde_json::Value>("sendall", &[serde_json::json!([miner.to_string()])])
            .expect("spend every wallet output");
        bitcoind
            .client
            .generate_to_address(1, &miner)
            .expect("confirm the spend");
        assert!(
            funding_confirmed(&client, outpoint)
                .await
                .expect("a spent output does not change the funding tx"),
            "the funding tx stays confirmed after the claim spends its output"
        );
    }

    /// A failed read of the funding tx is no answer, so the claim waits for the next retry tick
    /// rather than take the only child slot of a refill that may be unconfirmed.
    #[tokio::test]
    async fn a_failed_read_of_the_funding_tx_holds_the_claim() {
        let unreachable = BitcoinClient::new(
            "http://127.0.0.1:1".to_string(),
            RpcAuth::UserPass("user".to_string(), "password".to_string()),
            Some(1),
            Some(0),
            None,
        )
        .expect("rpc client");

        let confirmed = funding_confirmed(&unreachable, OutPoint::new(Txid::all_zeros(), 0)).await;

        assert!(
            matches!(confirmed, Err(ExecutorError::BitcoinRpcErr(_))),
            "an unread funding tx is not confirmed, got {confirmed:?}"
        );
    }

    /// An output that covers the fee and non-dust change funds the transaction, and one that
    /// leaves dust does not.
    #[tokio::test]
    async fn connector_funding_leaves_non_dust_change() {
        let bitcoind = Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind starts");
        mature_node_funds(&bitcoind);
        let mut wallet = test_wallet(&bitcoind).await;
        let template = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![],
        };
        let rate = FeeRate::from_sat_per_vb(100).expect("valid rate");
        let connector = Amount::from_sat(700);
        let dust = wallet.general().script_pubkey().minimal_non_dust();
        let fee = chain::funded_tx_fee(
            &template,
            InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
            rate,
        )
        .expect("no overflow");
        let exact = fee + dust - connector;

        fund_general(&bitcoind, &mut wallet, &[exact - Amount::ONE_SAT]).await;
        assert!(
            chain::select_connector_funding(
                &mut wallet,
                LeaseOwner::BridgeProof,
                &template,
                connector,
                rate
            )
            .is_err(),
            "an output that leaves dust must not fund the transaction"
        );

        fund_general(
            &bitcoind,
            &mut wallet,
            &[exact + Amount::from_sat(5_000), exact],
        )
        .await;
        let funding = chain::select_connector_funding(
            &mut wallet,
            LeaseOwner::BridgeProof,
            &template,
            connector,
            rate,
        )
        .expect("an output covers the fee");

        assert!(
            funding.input.txout.value >= exact,
            "the selected input covers the exact fee"
        );
        assert_eq!(funding.fee, fee, "the funding records the fee it pays");
        assert!(funding.change.value >= dust, "the change stays above dust");
        assert_eq!(
            funding.change.value,
            connector + funding.input.txout.value - fee,
            "the change is the connector and the input less the fee"
        );
        assert!(
            wallet.leased_outpoints().contains(&funding.input.outpoint),
            "the selected input is leased"
        );
    }

    /// The wallet view is stale after a failed sync, so a refill that may be live keeps its inputs.
    #[tokio::test]
    async fn a_failed_sync_after_a_refill_keeps_the_inputs_held() {
        let bitcoind = Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind starts");
        mature_node_funds(&bitcoind);
        let mut wallet = test_wallet(&bitcoind).await;
        fund_general(&bitcoind, &mut wallet, &[Amount::from_sat(100_000)]).await;
        let (input, refill_lease) = wallet
            .select_general_utxo(LeaseOwner::ClaimFundingRefill, Amount::ONE_SAT)
            .expect("the input is selectable");

        drop(bitcoind);
        chain::release_after_sync(&mut wallet, refill_lease)
            .await
            .expect_err("sync fails");

        assert_eq!(
            wallet.leased_outpoints(),
            BTreeSet::from([input.outpoint]),
            "the lease must outlive the duty"
        );
    }

    #[test]
    fn reused_claim_funding_must_hold_the_graph_amount() {
        let value = Amount::from_sat(100_000);
        let outpoint = OutPoint::new(Txid::from_byte_array([7; 32]), 0);
        let reservation = |value| ClaimFundingReservation {
            outpoint,
            txout: TxOut {
                value,
                script_pubkey: ScriptBuf::new(),
            },
        };

        assert_eq!(
            check_claim_funding(&reservation(value), value).ok(),
            Some(outpoint),
            "a reservation holding the graph's amount must be reused"
        );
        assert!(
            matches!(
                check_claim_funding(&reservation(Amount::from_sat(90_000)), value),
                Err(ExecutorError::ClaimFundingMismatch { .. })
            ),
            "a reservation of another amount must be rejected even though this node holds it"
        );
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
}
