//! Handles duties related to presigning of the
//! [`strata_bridge_tx_graph::peg_out_graph::PegOutGraph`] and the broadcasting of the [`Deposit
//! Transaction`](strata_bridge_tx_graph::transactions::deposit::DepositTx).
use std::collections::{BTreeMap, HashSet};

use bdk_wallet::{miniscript::ToPublicKey, Wallet};
use bitcoin::{
    hashes::{sha256, Hash},
    sighash::{Prevouts, SighashCache},
    taproot, FeeRate, OutPoint, Psbt, TapSighashType, Txid,
};
use btc_notify::client::TxStatus;
use musig2::{PartialSignature, PubNonce};
use secp256k1::{schnorr, Message};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v1::traits::*;
use strata_bridge_db::{persistent::sqlite::SqliteDb, public::PublicDb};
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_primitives::scripts::taproot::TaprootWitness;
use strata_bridge_stake_chain::{stake_chain::StakeChainInputs, transactions::stake::StakeTxData};
use strata_bridge_tx_graph::{
    pog_musig_functor::PogMusigF,
    transactions::{deposit::DepositTx, prelude::CovenantTx},
};
use strata_p2p_types::{P2POperatorPubKey, Scope, SessionId, StakeChainId};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::{
    contract_manager::{ExecutionConfig, OutputHandles},
    contract_state_machine::{SyntheticEvent, TransitionErr},
    errors::ContractManagerErr,
    executors::wots_handler::get_wots_pks,
    s2_session_manager::{MusigSessionErr, MusigSessionManager},
    tx_driver::TxDriver,
};

/// Handles the duty to publish the stake chain exchange message to the p2p network upon genesis and
/// when nagged.
pub(crate) async fn handle_publish_stake_chain_exchange(
    cfg: &ExecutionConfig,
    s2_client: &SecretServiceClient,
    db: &SqliteDb,
    msg_handler: &MessageHandler,
) -> Result<(), ContractManagerErr> {
    let pov_idx = cfg.operator_table.pov_idx();
    let general_key = s2_client
        .general_wallet_signer()
        .pubkey()
        .await?
        .to_x_only_pubkey();

    if let Some(pre_stake) = db
        .get_pre_stake(pov_idx)
        .await
        .expect("should be able to consult the database")
    {
        let stake_chain_id = StakeChainId::from_bytes([0u8; 32]);
        info!(%stake_chain_id, "broadcasting pre-stake information");

        msg_handler
            .send_stake_chain_exchange(stake_chain_id, general_key, pre_stake.txid, pre_stake.vout)
            .await;

        return Ok(());
    }

    error!("pre-stake information does exist in the database");

    Err(TransitionErr(
        "pre-stake information missing in the database".to_string(),
    ))?
}

/// Constructs and broadcasts the data required to generate this operator's
/// [`PegOutGraph`](strata_bridge_tx_graph::peg_out_graph::PegOutGraph) to the p2p network.
pub(crate) async fn handle_publish_deposit_setup(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    deposit_txid: Txid,
    deposit_idx: u32,
    stake_chain_inputs: StakeChainInputs,
) -> Result<(), ContractManagerErr> {
    info!(%deposit_txid, "executing duty to publish deposit setup");

    let OutputHandles {
        wallet,
        msg_handler,
        s2_session_manager,
        tx_driver,
        db,
        ..
    } = output_handles;
    let MusigSessionManager { s2_client, .. } = &s2_session_manager;

    let pov_idx = cfg.operator_table.pov_idx();
    let scope = Scope::from_bytes(deposit_txid.as_raw_hash().to_byte_array());
    let operator_pk = s2_client.general_wallet_signer().pubkey().await?;

    let wots_pks = get_wots_pks(deposit_txid, s2_client).await?;

    // this duty is generated not only when a deposit request is observed
    // but also when nagged by other operators.
    // to avoid creating a new stake input, we first check the database.
    info!(%deposit_txid, %deposit_idx, "checking if deposit data already exists");
    if let Ok(Some(stake_data)) = db.get_stake_data(pov_idx, deposit_idx).await {
        info!(%deposit_txid, %deposit_idx, "broadcasting deposit setup message from db");
        let stakechain_preimg_hash = stake_data.hash;
        let funding_outpoint = stake_data.operator_funds;

        msg_handler
            .send_deposit_setup(
                deposit_idx,
                scope,
                stakechain_preimg_hash,
                funding_outpoint,
                operator_pk,
                wots_pks,
            )
            .await;

        return Ok(());
    }

    info!(%deposit_txid, %deposit_idx, "constructing deposit setup message");
    let StakeChainInputs {
        stake_inputs,
        pre_stake_outpoint,
        ..
    } = stake_chain_inputs;

    info!(%deposit_txid, %deposit_idx, "querying for preimage");
    let stakechain_preimg = s2_client
        .stake_chain_preimages()
        .get_preimg(
            pre_stake_outpoint.txid,
            pre_stake_outpoint.vout,
            deposit_idx,
        )
        .await?;

    let stakechain_preimg_hash = sha256::Hash::hash(&stakechain_preimg);

    // check if there's a funding outpoint already for this stake index
    // otherwise, find a new unspent one from operator wallet and filter out all the
    // outpoints already in the db

    info!(%deposit_txid, %deposit_idx, "fetching funding outpoint for the stake transaction");
    let ignore = stake_inputs
        .values()
        .map(|input| input.operator_funds.to_owned())
        .collect::<HashSet<OutPoint>>();

    let mut wallet = wallet.write().await;
    info!("syncing wallet before fetching funding utxos for the stake");

    match wallet.sync().await {
        Ok(()) => info!("synced wallet successfully"),
        Err(e) => error!(?e, "could not sync wallet but proceeding regardless"),
    }

    info!(?ignore, "acquiring claim funding utxo");
    let (funding_op, remaining) = wallet.claim_funding_utxo(|op| ignore.contains(op));
    info!("operator wallet has {remaining} unassigned claim funding utxos remaining");

    let funding_utxo = match funding_op {
        Some(outpoint) => outpoint,
        None => {
            warn!("could not acquire claim funding utxo. attempting refill...");
            // The first time we run the node, it may be the case that the wallet starts off
            // empty.
            let psbt = wallet.refill_claim_funding_utxos(FeeRate::BROADCAST_MIN)?;
            finalize_claim_funding_tx(s2_client, tx_driver, wallet.general_wallet(), psbt).await?;
            wallet.sync().await.map_err(|e| {
                error!(?e, "could not sync wallet after refilling funding utxos");
                ContractManagerErr::FatalErr(
                    format!("could not sync wallet after refilling funding utxos: {e:?}").into(),
                )
            })?;

            wallet
                .claim_funding_utxo(|op| ignore.contains(op))
                .0
                .expect("no funding utxos available even after refill")
        }
    };

    // store the stake data eagerly to the database so that we minimize the risk of losing our own
    // data _after_ sending it out to peers.
    info!(%deposit_txid, %deposit_idx, "storing stake data in the database");
    let stake_data = StakeTxData {
        operator_funds: funding_utxo,
        hash: stakechain_preimg_hash,
        withdrawal_fulfillment_pk: wots_pks.withdrawal_fulfillment.into(),
        operator_pubkey: operator_pk,
    };

    output_handles
        .db
        .add_stake_data(pov_idx, deposit_idx, stake_data)
        .await
        .inspect_err(|e| {
            error!(
                ?e,
                "could not store this operator's stake data in the database"
            );
        })?;

    info!(%deposit_txid, %deposit_idx, "broadcasting deposit setup message");
    msg_handler
        .send_deposit_setup(
            deposit_idx,
            scope,
            stakechain_preimg_hash,
            funding_utxo,
            operator_pk,
            wots_pks.clone(),
        )
        .await;

    Ok(())
}

async fn finalize_claim_funding_tx(
    s2_client: &SecretServiceClient,
    tx_driver: &TxDriver,
    general_wallet: &Wallet,
    psbt: Psbt,
) -> Result<(), ContractManagerErr> {
    let mut tx = psbt.unsigned_tx;
    let txins_as_outs = tx
        .input
        .iter()
        .map(|txin| {
            general_wallet
                .get_utxo(txin.previous_output)
                .expect("always have this output because the wallet selected it in the first place")
                .txout
        })
        .collect::<Vec<_>>();
    let mut sighasher = SighashCache::new(&mut tx);
    let sighash_type = TapSighashType::All;
    let prevouts = Prevouts::All(&txins_as_outs);
    for input_index in 0..txins_as_outs.len() {
        let sighash = sighasher
            .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
            .expect("failed to construct sighash");
        let signature = s2_client
            .general_wallet_signer()
            .sign(&sighash.to_byte_array(), None)
            .await?;

        let signature = taproot::Signature {
            signature,
            sighash_type,
        };
        sighasher
            .witness_mut(input_index)
            .expect("an input here")
            .push(signature.to_vec());
    }

    info!(
        txid = %tx.compute_txid(),
        "submitting claim funding tx to the tx driver"
    );
    tx_driver
        .drive(tx, TxStatus::is_buried)
        .await
        .map_err(|e| ContractManagerErr::FatalErr(Box::new(e)))?;

    Ok(())
}

/// Handles the duty to publish the graph nonces for the given peg out graph identified by the
/// transaction ID of its claim transaction.
// TODO(@storopoli): This also commits the graph nonces to the database in the `pub_nonces` table.
pub(crate) async fn handle_publish_graph_nonces(
    musig: &MusigSessionManager,
    message_handler: &MessageHandler,
    claim_txid: Txid,
    pog_outpoints: PogMusigF<OutPoint>,
    pog_witnesses: PogMusigF<TaprootWitness>,
    pre_generated_nonces: Option<PogMusigF<PubNonce>>,
) -> Result<(), ContractManagerErr> {
    info!(%claim_txid, "executing duty to publish graph nonces");

    let nonces: PogMusigF<PubNonce> = if let Some(existing_nonces) = pre_generated_nonces {
        debug!(%claim_txid, "using pre-generated nonces from contract state");
        existing_nonces
    } else {
        debug!(%claim_txid, "generating new nonces via secret service");
        match PogMusigF::transpose_result(
            pog_outpoints
                .clone()
                .zip(pog_witnesses.clone())
                .map(|(outpoint, witness)| musig.get_nonce(outpoint, witness))
                .join_all()
                .await,
        ) {
            Ok(res) => res,
            Err(err) => {
                match err {
                    MusigSessionErr::SecretServiceClientErr(client_error) => {
                        warn!(%client_error, "error getting nonces for graph from s2")
                    }
                    MusigSessionErr::SecretServiceNewSessionErr(musig2_new_session_error) => {
                        // TODO: (@Rajil1213) handle this properly when we known what causes this
                        error!(
                            ?musig2_new_session_error,
                            "error getting nonces for graph from s2"
                        )
                    }
                    MusigSessionErr::SecretServiceRoundContributionErr(
                        round_contribution_error,
                    ) => {
                        // TODO: (@Rajil1213) handle this properly when we known what causes this
                        error!(
                            ?round_contribution_error,
                            "error getting nonces for graph from s2"
                        )
                    }
                    MusigSessionErr::SecretServiceRoundFinalizeErr(round_finalize_error) => {
                        // TODO: (@Rajil1213) handle this properly when we known what causes this
                        error!(%round_finalize_error, "error getting nonces for graph from s2")
                    }
                    MusigSessionErr::Premature => {
                        unreachable!("this should never happen unless the stf is wrong")
                    }
                    MusigSessionErr::NotFound(out_point) => {
                        // this can happen either because the session has already been finalized
                        // or if the contract is unknown to us
                        // both of which are okay but we do log it here.
                        warn!(%out_point, "session outpoint not found");
                    }
                }

                return Ok(());
            }
        }
    };

    // TODO(@storopoli): Commit the graph nonces to the database in the `pub_nonces` table.
    //                   This function should take a `&SqliteDB` handle as an argument.

    // TODO(@storopoli): Commit the graph witnesses to the database in the `witnesses` table.
    //                   This function should take a `&SqliteDB` handle as an argument.

    info!(%claim_txid, "publishing graph nonces");
    message_handler
        .send_musig2_nonces(
            SessionId::from_bytes(claim_txid.to_byte_array()),
            nonces.pack(),
        )
        .await;

    Ok(())
}

/// Handles the duty to publish the graph partial signatures for the given peg out graph identified
/// by the transaction ID of its claim transaction.
// TODO(@storopoli): This also commits the graph partial signatures to the database in the
// `partial_signatures` table.
pub(crate) async fn handle_publish_graph_sigs(
    musig: &MusigSessionManager,
    message_handler: &MessageHandler,
    claim_txid: Txid,
    pubnonces: BTreeMap<secp256k1::PublicKey, PogMusigF<PubNonce>>,
    pog_outpoints: PogMusigF<OutPoint>,
    pog_sighashes: PogMusigF<Message>,
    pre_generated_partial_signatures: Option<PogMusigF<PartialSignature>>,
) -> Result<(), ContractManagerErr> {
    info!(%claim_txid, "executing duty to publish graph signatures");

    let partial_sigs: PogMusigF<PartialSignature> =
        if let Some(existing_sigs) = pre_generated_partial_signatures {
            debug!(%claim_txid, "using pre-generated graph signatures from contract state");
            existing_sigs
        } else {
            debug!(%claim_txid, "generating new graph signatures via secret service");

            // Add all nonces to the musig session manager context.
            for (pk, graph_nonces) in pubnonces {
                trace!(%pk, "loading nonces");

                PogMusigF::<()>::transpose_result::<MusigSessionErr>(
                    pog_outpoints
                        .clone()
                        .zip(graph_nonces)
                        .map(|(outpoint, nonce)| {
                            musig.put_nonce(outpoint, pk.to_x_only_pubkey(), nonce)
                        })
                        .join_all()
                        .await,
                )?;
            }

            info!(%claim_txid, "getting all partials");
            PogMusigF::transpose_result(
                pog_outpoints
                    .clone()
                    .zip(pog_sighashes)
                    .map(|(op, sighash)| musig.get_partial(op, sighash))
                    .join_all()
                    .await,
            )
            .inspect_err(|e| {
                error!(
                    %claim_txid,
                    ?e,
                    "failed to get partials for graph signatures"
                );
            })?
        };

    // TODO(@storopoli): Commit the graph partial signatures to the database in the
    //                   `partial_signatures` table. This function should take a `&SqliteDB`
    //                   handle as an argument.

    info!(%claim_txid, "publishing graph signatures");
    message_handler
        .send_musig2_signatures(
            SessionId::from_bytes(claim_txid.to_byte_array()),
            partial_sigs.pack(),
        )
        .await;

    Ok(())
}

/// Handles the duty to commit the aggregate signatures for the given peg out graph identified by
/// the deposit txid.
///
/// This produces a [`ContractEvent::AggregateSigs`] event which is sent via the
/// `ouroboros_event_sender` to the node itself so that the state can be updated with the aggregate
/// signatures.
pub(crate) async fn handle_commit_sig(
    cfg: &ExecutionConfig,
    deposit_txid: Txid,
    s2_session_manager: &MusigSessionManager,
    synthetic_event_sender: &mpsc::UnboundedSender<SyntheticEvent>,
    pog_inpoints: BTreeMap<Txid, PogMusigF<OutPoint>>,
    pog_sighash_types: BTreeMap<Txid, PogMusigF<TapSighashType>>,
    graph_partials: BTreeMap<Txid, BTreeMap<P2POperatorPubKey, PogMusigF<PartialSignature>>>,
) -> Result<(), ContractManagerErr> {
    let mut graph_sigs = BTreeMap::new();

    for (claim_txid, operator_partials) in graph_partials {
        let Some(inpoints) = pog_inpoints.get(&claim_txid) else {
            error!(%claim_txid, "no inpoints found for claim txid");

            return Err(
                TransitionErr(format!("inpoints missing for claim txid {claim_txid}")).into(),
            );
        };

        let Some(sighash_types) = pog_sighash_types.get(&claim_txid) else {
            error!(%claim_txid, "no sighash types found for claim txid");

            return Err(TransitionErr(format!(
                "sighash types missing for claim txid {claim_txid}"
            ))
            .into());
        };

        for (pk, partials) in operator_partials {
            let pk = cfg
                .operator_table
                .op_key_to_btc_key(&pk)
                .expect("signer must be known")
                .x_only_public_key()
                .0;

            // TODO: (@Rajil1213) use the batching API instead
            PogMusigF::<()>::transpose_result::<MusigSessionErr>(
                inpoints
                    .clone()
                    .zip(partials)
                    .map(|(inpoint, partial)| {
                        s2_session_manager.put_partial(inpoint, pk.to_x_only_pubkey(), partial)
                    })
                    .join_all()
                    .await,
            )?;
        }

        let agg_sigs_for_graph = PogMusigF::transpose_result::<MusigSessionErr>(
            inpoints
                .clone()
                .map(|inpoint| s2_session_manager.get_signature(inpoint))
                .join_all()
                .await,
        )?;

        let agg_sigs_for_graph =
            agg_sigs_for_graph
                .zip(sighash_types.clone())
                .map(|(sig, sighash_type)| taproot::Signature {
                    signature: schnorr::Signature::from_slice(&sig.serialize())
                        .expect("lifted signature must be a valid schnorr signature"),
                    sighash_type,
                });

        graph_sigs.insert(claim_txid, agg_sigs_for_graph);
    }

    synthetic_event_sender
        .send(SyntheticEvent::AggregatedSigs {
            deposit_txid,
            agg_sigs: graph_sigs,
        })
        .map_err(|e| {
            error!(%e, "could not send aggregate sigs event");

            // usually means the receiver is dropped i.e., the event loop has crashed.
            ContractManagerErr::FatalErr(
                format!("could not send aggregate sigs event due to {e}").into(),
            )
        })?;

    Ok(())
}

/// Handles the duty to publish the root nonce for the given deposit request identified by the
/// its prevout i.e., the outpoint of the Deposit Request Transaction.
// TODO(@storopoli): This also commits the root nonce to the database in the `pub_nonces` table.
pub(crate) async fn handle_publish_root_nonce(
    s2_client: &MusigSessionManager,
    msg_handler: &MessageHandler,
    prevout: OutPoint,
    witness: TaprootWitness,
    pre_generated_nonce: Option<PubNonce>,
) -> Result<(), ContractManagerErr> {
    let deposit_request_txid = prevout.txid;
    let deposit_request_vout = prevout.vout;
    info!(%deposit_request_txid, %deposit_request_vout, "executing duty to publish root nonce");

    let nonce = if let Some(existing_nonce) = pre_generated_nonce {
        debug!(%deposit_request_txid, %deposit_request_vout, "using pre-generated root nonce from contract state");
        existing_nonce
    } else {
        debug!(%deposit_request_txid, %deposit_request_vout, "generating new root nonce via secret service");
        s2_client.get_nonce(prevout, witness.clone()).await?
    };

    // TODO(@storopoli): Commit the root nonce to the database in the `pub_nonces` table.
    //                   This function should take a `&SqliteDB` handle as an argument.

    // TODO(@storopoli): Commit the root witness to the database in the `witnesses` table.
    //                   This function should take a `&SqliteDB` handle as an argument.

    info!(%deposit_request_txid, %deposit_request_vout, "publishing root nonce");
    msg_handler
        .send_musig2_nonces(
            SessionId::from_bytes(deposit_request_txid.to_byte_array()),
            vec![nonce],
        )
        .await;

    Ok(())
}

/// Handles the duty to publish the root signature for the given deposit request identified by the
/// its prevout i.e., the outpoint of the Deposit Request Transaction.
// TODO(@storopoli): This also commits the root signature to the database in the
// `partial_signatures` table.
pub(crate) async fn handle_publish_root_signature(
    cfg: &ExecutionConfig,
    s2_client: &MusigSessionManager,
    msg_handler: &MessageHandler,
    nonces: BTreeMap<secp256k1::PublicKey, PubNonce>,
    prevout: OutPoint,
    sighash: Message,
    pre_generated_partial_signature: Option<PartialSignature>,
) -> Result<(), ContractManagerErr> {
    let deposit_request_txid = prevout.txid;
    let deposit_request_vout = prevout.vout;
    info!(%deposit_request_txid, "executing duty to publish root signature");

    let partial_sig = if let Some(existing_sig) = pre_generated_partial_signature {
        debug!(%deposit_request_txid, %deposit_request_vout, "using pre-generated root signature from contract state");
        existing_sig
    } else {
        debug!(%deposit_request_txid, %deposit_request_vout, "generating new root signature via secret service");

        let our_pubkey = cfg.operator_table.pov_btc_key();
        for (musig2_pubkey, nonce) in nonces.into_iter().filter(|(pk, _)| *pk != our_pubkey) {
            trace!(%musig2_pubkey, %deposit_request_txid, "loading nonce");
            s2_client
                .put_nonce(prevout, musig2_pubkey.to_x_only_pubkey(), nonce)
                .await
                .inspect_err(|e| {
                    error!(
                        %deposit_request_txid,
                        %musig2_pubkey,
                        ?e,
                        "failed to load nonce"
                    );
                })?;
        }

        info!(%deposit_request_txid, %deposit_request_vout, "getting partial signature");
        s2_client.get_partial(prevout, sighash).await?
    };

    // TODO(@storopoli): Commit the root signature to the database in the `partial_signatures`
    //                   table. This function should take a `&SqliteDB` handle as an argument.

    info!(%deposit_request_txid, %deposit_request_vout, "publishing root signature");
    msg_handler
        .send_musig2_signatures(
            SessionId::from_bytes(prevout.txid.as_raw_hash().to_byte_array()),
            vec![partial_sig],
        )
        .await;

    Ok(())
}

/// Handles the duty to publish the deposit transaction to bitcoin by finalizing it with the
/// aggregate of all the partial signatures.
pub(crate) async fn handle_publish_deposit(
    musig: &MusigSessionManager,
    tx_driver: &TxDriver,
    deposit_tx: DepositTx,
    partials: BTreeMap<secp256k1::PublicKey, PartialSignature>,
) -> Result<(), ContractManagerErr> {
    info!(deposit_txid=%deposit_tx.compute_txid(), "executing duty to publish deposit");

    let prevout = deposit_tx
        .psbt()
        .unsigned_tx
        .input
        .first()
        .unwrap()
        .previous_output;

    for (pk, partial) in partials {
        musig
            .put_partial(prevout, pk.to_x_only_pubkey(), partial)
            .await?;
    }

    let sig = musig.get_signature(prevout).await?;
    let schnorr_sig = schnorr::Signature::from_slice(&sig.serialize())
        .expect("must be a valid schnorr signature");
    let taproot_sig = taproot::Signature {
        signature: schnorr_sig,
        sighash_type: TapSighashType::All,
    };

    let mut sighasher = SighashCache::new(deposit_tx.psbt().unsigned_tx.clone());

    let deposit_tx_witness = sighasher.witness_mut(0).expect("must have first input");
    deposit_tx_witness.push(taproot_sig.to_vec());

    if let TaprootWitness::Script {
        script_buf,
        control_block,
    } = &deposit_tx.witnesses()[0]
    {
        deposit_tx_witness.push(script_buf.to_bytes());
        deposit_tx_witness.push(control_block.serialize());
    }

    let tx = sighasher.into_transaction();

    info!(txid = %tx.compute_txid(), "broadcasting deposit tx");
    tx_driver
        .drive(tx, TxStatus::is_buried)
        .await
        .expect("deposit tx should get confirmed");

    Ok(())
}
