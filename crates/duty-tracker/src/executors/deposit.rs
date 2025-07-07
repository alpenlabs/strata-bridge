//! Handles duties related to presigning of the
//! [`strata_bridge_tx_graph::peg_out_graph::PegOutGraph`] and the broadcasting of the [`Deposit
//! Transaction`](strata_bridge_tx_graph::transactions::deposit::DepositTx).
use std::{collections::HashSet, sync::Arc};

use algebra::predicate;
use bdk_wallet::{miniscript::ToPublicKey, Wallet};
use bitcoin::{
    hashes::{sha256, Hash},
    sighash::{Prevouts, SighashCache},
    taproot, FeeRate, OutPoint, Psbt, TapSighashType, Txid, XOnlyPublicKey,
};
use btc_notify::client::TxStatus;
use futures::FutureExt;
use musig2::{aggregate_partial_signatures, AggNonce, PartialSignature, PubNonce};
use secp256k1::{schnorr, Message, PublicKey};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::*;
use strata_bridge_db::{persistent::sqlite::SqliteDb, public::PublicDb};
use strata_bridge_p2p_service::MessageHandler;
use strata_bridge_primitives::{key_agg::create_agg_ctx, scripts::taproot::TaprootWitness};
use strata_bridge_stake_chain::{stake_chain::StakeChainInputs, transactions::stake::StakeTxData};
use strata_bridge_tx_graph::{
    pog_musig_functor::PogMusigF,
    transactions::{deposit::DepositTx, prelude::CovenantTx},
};
use strata_p2p_types::{Scope, SessionId, StakeChainId};
use tracing::{debug, error, info, warn};

use crate::{
    contract_manager::{ExecutionConfig, OutputHandles},
    contract_state_machine::TransitionErr,
    errors::ContractManagerErr,
    executors::wots_handler::get_wots_pks,
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
    output_handles: Arc<OutputHandles>,
    deposit_txid: Txid,
    deposit_idx: u32,
    stake_chain_inputs: StakeChainInputs,
) -> Result<(), ContractManagerErr> {
    info!(%deposit_txid, "executing duty to publish deposit setup");

    let OutputHandles {
        wallet,
        msg_handler,
        s2_client,
        tx_driver,
        db,
        ..
    } = output_handles.as_ref();

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
    let (funding_op, remaining) = wallet.claim_funding_utxo(predicate::never);
    info!("operator wallet has {remaining} unassigned claim funding utxos remaining");

    let funding_utxo = match funding_op {
        Some(outpoint) => outpoint,
        None => {
            warn!("could not acquire claim funding utxo. attempting refill...");
            // The first time we run the node, it may be the case that the wallet starts off
            // empty.
            let psbt = wallet
                .refill_claim_funding_utxos(FeeRate::BROADCAST_MIN, cfg.stake_funding_pool_size)?;
            finalize_claim_funding_tx(s2_client, tx_driver, wallet.general_wallet(), psbt).await?;
            wallet.sync().await.map_err(|e| {
                error!(?e, "could not sync wallet after refilling funding utxos");
                ContractManagerErr::FatalErr(format!(
                    "could not sync wallet after refilling funding utxos: {e:?}"
                ))
            })?;

            wallet
                .claim_funding_utxo(predicate::never)
                .0
                .expect("no funding utxos available even after refill")
        }
    };

    if remaining <= cfg.stake_funding_pool_size as u64 / 2 {
        let pool_size = cfg.stake_funding_pool_size;
        let outs = output_handles.clone();
        tokio::spawn(async move {
            info!("refilling claim funding utxo pool to size of {pool_size}");
            let mut wallet = outs.wallet.write().await;
            let psbt = wallet
                .refill_claim_funding_utxos(FeeRate::BROADCAST_MIN, pool_size)
                .expect("could not construct claim funding tx");
            finalize_claim_funding_tx(
                &outs.s2_client,
                &outs.tx_driver,
                wallet.general_wallet(),
                psbt,
            )
            .await
            .expect("could not finalize claim funding tx");
            debug!("claim funding utxo pool refilled");
        });
    }

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

    let txid = tx.compute_txid();
    info!(%txid, "submitting claim funding tx to the tx driver");
    tx_driver
        .drive(tx, predicate::eq(TxStatus::Mempool)) // It's our tx, we won't double spend
        .await
        .map_err(|e| ContractManagerErr::FatalErr(e.to_string()))?;

    info!(%txid, "claim funding tx detected in mempool");

    Ok(())
}

/// Handles the duty to publish the graph nonces for the given peg out graph identified by the
/// transaction ID of its claim transaction.
// TODO(@storopoli): This also commits the graph nonces to the database in the `pub_nonces` table.
pub(crate) async fn handle_publish_graph_nonces(
    s2_client: &SecretServiceClient,
    musig_pubkeys: Vec<XOnlyPublicKey>,
    message_handler: &MessageHandler,
    claim_txid: Txid,
    pog_outpoints: PogMusigF<OutPoint>,
    pog_witnesses: PogMusigF<TaprootWitness>,
    pre_generated_nonces: Option<PogMusigF<PubNonce>>,
) -> Result<(), ContractManagerErr> {
    info!(%claim_txid, "executing duty to publish graph nonces");

    let musig_client = s2_client.musig2_signer();

    let nonces: PogMusigF<PubNonce> = if let Some(existing_nonces) = pre_generated_nonces {
        debug!(%claim_txid, "using pre-generated nonces from contract state");
        existing_nonces
    } else {
        debug!(%claim_txid, "generating new nonces via secret service");
        PogMusigF::transpose_result(
            pog_outpoints
                .clone()
                .zip(pog_witnesses.clone())
                .map(|(outpoint, witness)| {
                    let params = Musig2Params {
                        ordered_pubkeys: musig_pubkeys.clone(),
                        witness,
                        input: outpoint,
                    };
                    musig_client
                        .get_pub_nonce(params)
                        .map(|f| f.map(|r| r.expect("our pubkey is in params")))
                })
                .join_all()
                .await,
        )?
    };

    // TODO(@storopoli): Commit the graph nonces to the database in the `pub_nonces` table.
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

/// The information required to generate the Musig2 partial signature for an input in the peg out
/// graph.
pub(crate) struct GenPartialsInput {
    /// The [`musig2`] aggregated nonce.
    pub(crate) aggnonce: AggNonce,

    /// The input being signed represented as an [`OutPoint`].
    pub(crate) outpoint: OutPoint,

    /// The sighash of the transaction being signed for this input.
    pub(crate) sighash: Message,

    /// The type of spending path to be used which determines how the keys are aggregated in
    /// [`musig2`].
    pub(crate) witness: TaprootWitness,
}

/// Handles the duty to publish the graph partial signatures for the given peg out graph identified
/// by the transaction ID of its claim transaction.
// TODO(@storopoli): This also commits the graph partial signatures to the database in the
// `partial_signatures` table.
pub(crate) async fn handle_publish_graph_sigs(
    s2_client: &SecretServiceClient,
    musig_pubkeys: Vec<XOnlyPublicKey>,
    message_handler: &MessageHandler,
    claim_txid: Txid,
    input_data: PogMusigF<GenPartialsInput>,
    pre_generated_partial_signatures: Option<PogMusigF<PartialSignature>>,
) -> Result<(), ContractManagerErr> {
    info!(%claim_txid, "executing duty to publish graph signatures");

    let musig2_signer = s2_client.musig2_signer();

    let partial_sigs = if let Some(existing_partials) = pre_generated_partial_signatures {
        debug!(%claim_txid, "using pre-generated partials from contract state");

        existing_partials
    } else {
        let partial_sigs_futures = input_data.map(|data| {
            let GenPartialsInput {
                aggnonce,
                outpoint,
                sighash,
                witness,
            } = data;

            let musig_params = Musig2Params {
                ordered_pubkeys: musig_pubkeys.clone(),
                witness,
                input: outpoint,
            };

            musig2_signer
                .get_our_partial_sig(musig_params, aggnonce, *sighash.as_ref())
                .map(|f| f.map(|r| r.expect("good partial sig")))
        });

        PogMusigF::transpose_result(partial_sigs_futures.join_all().await).inspect_err(|e| {
            error!(
                %claim_txid,
                ?e,
                "failed to get partials for graph"
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

/// Handles the duty to publish the root nonce for the given deposit request identified by the
/// its prevout i.e., the outpoint of the Deposit Request Transaction.
// TODO(@storopoli): This also commits the root nonce to the database in the `pub_nonces` table.
pub(crate) async fn handle_publish_root_nonce(
    s2_client: &SecretServiceClient,
    musig_pubkeys: Vec<XOnlyPublicKey>,
    msg_handler: &MessageHandler,
    prevout: OutPoint,
    witness: TaprootWitness,
    pre_generated_nonce: Option<PubNonce>,
) -> Result<(), ContractManagerErr> {
    let deposit_request_txid = prevout.txid;
    let deposit_request_vout = prevout.vout;
    info!(%deposit_request_txid, %deposit_request_vout, "executing duty to publish root nonce");

    let musig2_params = Musig2Params {
        ordered_pubkeys: musig_pubkeys,
        witness,
        input: prevout,
    };

    let nonce = if let Some(existing_nonce) = pre_generated_nonce {
        debug!(%deposit_request_txid, %deposit_request_vout, "using pre-generated root nonce from contract state");
        existing_nonce
    } else {
        debug!(%deposit_request_txid, %deposit_request_vout, "generating new root nonce via secret service");
        s2_client
            .musig2_signer()
            .get_pub_nonce(musig2_params.clone())
            .await?
            .expect("our pubkey should be in params")
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
#[expect(clippy::too_many_arguments)]
pub(crate) async fn handle_publish_root_signature(
    s2_client: &SecretServiceClient,
    musig_pubkeys: Vec<XOnlyPublicKey>,
    msg_handler: &MessageHandler,
    aggnonce: AggNonce,
    prevout: OutPoint,
    sighash: Message,
    witness: TaprootWitness,
    pre_generated_partial_signature: Option<PartialSignature>,
) -> Result<(), ContractManagerErr> {
    let deposit_request_txid = prevout.txid;
    let deposit_request_vout = prevout.vout;
    info!(%deposit_request_txid, "executing duty to publish root signature");
    let musig2_signer = s2_client.musig2_signer();

    let partial_sig = if let Some(existing_sig) = pre_generated_partial_signature {
        debug!(%deposit_request_txid, %deposit_request_vout, "using pre-generated root signature from contract state");
        existing_sig
    } else {
        debug!(%deposit_request_txid, %deposit_request_vout, "generating new root signature via secret service");

        let params = Musig2Params {
            ordered_pubkeys: musig_pubkeys,
            witness,
            input: prevout,
        };

        info!(%deposit_request_txid, %deposit_request_vout, "getting partial signature");
        musig2_signer
            .get_our_partial_sig(params, aggnonce, *sighash.as_ref())
            .await?
            .expect("good partial sig")
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
    tx_driver: &TxDriver,
    musig_pubkeys: Vec<PublicKey>,
    deposit_tx: DepositTx,
    partials: Vec<PartialSignature>,
    aggnonce: AggNonce,
) -> Result<(), ContractManagerErr> {
    info!(deposit_txid=%deposit_tx.compute_txid(), "executing duty to publish deposit");
    let witness = &deposit_tx.witnesses()[0];

    let ctx = create_agg_ctx(musig_pubkeys.into_iter(), witness).expect("must create agg ctx");

    let sighash = deposit_tx.sighashes()[0];
    let aggregate_sig: schnorr::Signature =
        aggregate_partial_signatures(&ctx, &aggnonce, partials, sighash.as_ref())
            .expect("partial signatures must be valid");

    let sighash_type = deposit_tx.sighash_types()[0];
    let taproot_sig = taproot::Signature {
        signature: aggregate_sig,
        sighash_type,
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
