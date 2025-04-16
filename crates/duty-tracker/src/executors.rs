//! Contains execution logic for various duties emitted by the contract manager.

use std::{collections::HashSet, sync::Arc};

use alpen_bridge_params::prelude::StakeChainParams;
use bdk_wallet::{miniscript::ToPublicKey, SignOptions, Wallet};
use bitcoin::{
    hashes::{sha256, Hash},
    sighash::{Prevouts, SighashCache},
    FeeRate, OutPoint, Psbt, TapSighashType, Txid,
};
use bitcoin_bosd::Descriptor;
use bitvm::chunk::api::{NUM_HASH, NUM_PUBS, NUM_U256};
use futures::future::{join3, join_all};
use operator_wallet::FundingUtxo;
use secret_service_client::SecretServiceClient;
use secret_service_proto::v1::traits::*;
use strata_bridge_connectors::prelude::{
    ConnectorC0, ConnectorC1, ConnectorCpfp, ConnectorK, ConnectorNOfN, ConnectorStake,
};
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{build_context::BuildContext, constants::SEGWIT_MIN_AMOUNT};
use strata_bridge_stake_chain::{
    prelude::{StakeTx, OPERATOR_FUNDS, STAKE_VOUT},
    stake_chain::StakeChainInputs,
    transactions::stake::StakeTxData,
};
use strata_bridge_tx_graph::transactions::{
    claim::{ClaimData, ClaimTx},
    prelude::{WithdrawalFulfillment, WithdrawalMetadata},
};
use strata_p2p_types::{Scope, Wots128PublicKey, Wots256PublicKey, WotsPublicKeys};
use tracing::{debug, error, info};

use crate::{
    constants::{
        FIELD_ELEMENTS_PK_OFFSET, HASH_ELEMENTS_PK_OFFSET, PUBLIC_INPUTS_PK_OFFSET,
        WITHDRAWAL_FULFILLMENT_PK_IDX,
    },
    contract_manager::{ExecutionConfig, OutputHandles},
    errors::{ContractManagerErr, StakeChainErr},
    tx_driver::TxDriver,
};

/// Constructs and broadcasts the data required to generate this operator's
/// [`PegOutGraph`](strata_bridge_tx_graph::peg_out_graph::PegOutGraph) to the p2p network.
pub(super) async fn handle_publish_deposit_setup(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    deposit_idx: u32,
    deposit_txid: Txid,
    stake_chain_inputs: StakeChainInputs,
) -> Result<(), ContractManagerErr> {
    let pov_idx = cfg.operator_table.pov_idx();
    let scope = Scope::from_bytes(deposit_txid.as_raw_hash().to_byte_array());
    let operator_pk = output_handles
        .s2_client
        .general_wallet_signer()
        .pubkey()
        .await?;

    let wots_client = output_handles.s2_client.wots_signer();
    /// VOUT is static because irrelevant so we're just gonna use 0
    const VOUT: u32 = 0;
    let withdrawal_fulfillment = Wots256PublicKey::from_flattened_bytes(
        &wots_client
            .get_256_public_key(deposit_txid, VOUT, WITHDRAWAL_FULFILLMENT_PK_IDX)
            .await?,
    );
    const NUM_FQS: usize = NUM_U256;
    const NUM_PUB_INPUTS: usize = NUM_PUBS;
    const NUM_HASHES: usize = NUM_HASH;

    let public_inputs_ftrs: [_; NUM_PUB_INPUTS] = std::array::from_fn(|i| {
        wots_client.get_256_public_key(deposit_txid, VOUT, (i + PUBLIC_INPUTS_PK_OFFSET) as u32)
    });
    let fqs_ftrs: [_; NUM_FQS] = std::array::from_fn(|i| {
        wots_client.get_256_public_key(deposit_txid, VOUT, (i + FIELD_ELEMENTS_PK_OFFSET) as u32)
    });
    let hashes_ftrs: [_; NUM_HASHES] = std::array::from_fn(|i| {
        wots_client.get_128_public_key(deposit_txid, VOUT, (i + HASH_ELEMENTS_PK_OFFSET) as u32)
    });

    let (public_inputs, fqs, hashes) = join3(
        join_all(public_inputs_ftrs),
        join_all(fqs_ftrs),
        join_all(hashes_ftrs),
    )
    .await;

    info!(%deposit_txid, %deposit_idx, "constructing wots keys");
    let public_inputs = public_inputs
        .into_iter()
        .map(|result| result.map(|bytes| Wots256PublicKey::from_flattened_bytes(&bytes)))
        .collect::<Result<_, _>>()?;
    let fqs = fqs
        .into_iter()
        .map(|result| result.map(|bytes| Wots256PublicKey::from_flattened_bytes(&bytes)))
        .collect::<Result<_, _>>()?;
    let hashes = hashes
        .into_iter()
        .map(|result| result.map(|bytes| Wots128PublicKey::from_flattened_bytes(&bytes)))
        .collect::<Result<_, _>>()?;

    let wots_pks = WotsPublicKeys::new(withdrawal_fulfillment, public_inputs, fqs, hashes);

    // this duty is generated when this operator not only when a deposit request is observed
    // but also when nagged by other operators.
    // to avoid creating a new stake input, we first check the database.
    info!(%deposit_txid, %deposit_idx, "checking if deposit data already exists");
    if let Ok(Some(stake_data)) = output_handles.db.get_stake_data(pov_idx, deposit_idx).await {
        info!(%deposit_txid, %deposit_idx, "broadcasting deposit setup message from db");
        let stakechain_preimg_hash = stake_data.hash;
        let funding_outpoint = stake_data.operator_funds;

        output_handles
            .msg_handler
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
    let stakechain_preimg = output_handles
        .s2_client
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
        .iter()
        .map(|input| input.operator_funds.to_owned())
        .collect::<HashSet<OutPoint>>();

    let mut wallet = output_handles.wallet.write().await;
    info!("syncing wallet before fetching funding utxos for the stake");

    match wallet.sync().await {
        Ok(()) => info!("synced wallet successfully"),
        Err(e) => error!(?e, "could not sync wallet but proceeding regardless"),
    }

    info!(?ignore, "claiming funding utxos");
    let funding_op = wallet.claim_funding_utxo(|op| ignore.contains(&op));

    let funding_utxo = match funding_op {
        FundingUtxo::Available(outpoint) => outpoint,
        FundingUtxo::ShouldRefill { op, left } => {
            info!("refilling stakechain funding utxos, have {left} left");

            let psbt = wallet.refill_claim_funding_utxos(FeeRate::BROADCAST_MIN)?;
            finalize_claim_funding_tx(
                &output_handles.s2_client,
                &output_handles.tx_driver,
                wallet.general_wallet(),
                psbt,
            )
            .await?;

            op
        }
        FundingUtxo::Empty => {
            // The first time we run the node, it may be the case that the wallet starts off
            // empty.
            //
            // For every case afterwards, we should receive a `ShouldRefill` message before
            // the wallet is actually empty.
            let psbt = wallet.refill_claim_funding_utxos(FeeRate::BROADCAST_MIN)?;
            finalize_claim_funding_tx(
                &output_handles.s2_client,
                &output_handles.tx_driver,
                wallet.general_wallet(),
                psbt,
            )
            .await?;

            let funding_utxo = wallet.claim_funding_utxo(|op| ignore.contains(&op));

            match funding_utxo {
                FundingUtxo::Available(outpoint) => outpoint,
                _ => panic!("aaaaa no funding utxos available even after refill"),
            }
        }
    };

    info!(%deposit_txid, %deposit_idx, "constructing wots public keys for withdrawal fulfillment");
    let withdrawal_fulfillment_pk = std::array::from_fn(|i| wots_pks.withdrawal_fulfillment[i]);

    let stake_data = StakeTxData {
        operator_funds: funding_utxo,
        hash: stakechain_preimg_hash,
        withdrawal_fulfillment_pk: strata_bridge_primitives::wots::Wots256PublicKey(
            withdrawal_fulfillment_pk,
        ),
    };

    info!(%deposit_txid, %deposit_idx, "adding stake data to the database");
    debug!(%deposit_txid, %deposit_idx, ?stake_data, "adding stake data to the database");

    output_handles
        .db
        .add_stake_data(pov_idx, deposit_idx, stake_data)
        .await?;

    info!(%deposit_txid, %deposit_idx, "broadcasting deposit setup message");
    output_handles
        .msg_handler
        .send_deposit_setup(
            deposit_idx,
            scope,
            stakechain_preimg_hash,
            funding_utxo,
            operator_pk,
            wots_pks,
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

        let signature = bitcoin::taproot::Signature {
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
        .drive(tx)
        .await
        .map_err(|e| ContractManagerErr::FatalErr(Box::new(e)))?;

    Ok(())
}

/// Advances the stake chain by submitting the given transaction to the tx driver.
///
/// It is the responsibility of the caller to ensure that the supplied `stake_index` corresponds to
/// the provided `stake_tx`.
pub(super) async fn handle_advance_stake_chain(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    stake_index: u32,
    stake_tx: StakeTx,
) -> Result<(), ContractManagerErr> {
    let operator_id = cfg.operator_table.pov_idx();
    let op_p2p_key = cfg.operator_table.pov_op_key();

    let pre_stake_outpoint = output_handles
        .db
        .get_pre_stake(operator_id)
        .await?
        .ok_or(StakeChainErr::StakeSetupDataNotFound(op_p2p_key.clone()))?;

    let messages = stake_tx.sighashes();
    let funds_signature = output_handles
        .s2_client
        .general_wallet_signer()
        .sign(messages[0].as_ref(), None)
        .await?;

    let signed_stake_tx = if stake_index == 0 {
        // the first stake transaction spends the pre-stake which is locked by the key in the
        // stake-chain wallet
        let stake_signature = output_handles
            .s2_client
            .general_wallet_signer()
            .sign(messages[1].as_ref(), None)
            .await?;

        stake_tx.finalize_initial(funds_signature, stake_signature)
    } else {
        let pre_image_client = output_handles.s2_client.stake_chain_preimages();
        let OutPoint {
            txid: pre_stake_txid,
            vout: pre_stake_vout,
        } = pre_stake_outpoint;
        let prev_preimage = pre_image_client
            .get_preimg(pre_stake_txid, pre_stake_vout, stake_index - 1)
            .await?;
        let n_of_n_agg_pubkey = cfg
            .operator_table
            .tx_build_context(cfg.network)
            .aggregated_pubkey();
        let operator_pubkey = output_handles
            .s2_client
            .general_wallet_signer()
            .pubkey()
            .await?
            .to_x_only_pubkey();
        let stake_hash = pre_image_client
            .get_preimg(pre_stake_txid, pre_stake_vout, stake_index)
            .await?;
        let stake_hash = sha256::Hash::hash(&stake_hash);
        let StakeChainParams { delta, .. } = cfg.stake_chain_params;
        let prev_connector_s = ConnectorStake::new(
            n_of_n_agg_pubkey,
            operator_pubkey,
            stake_hash,
            delta,
            cfg.network,
        );

        // all the stake transactions except the first one are locked with the general wallet
        // signer.
        // this is a caveat of the fact that we only share one x-only pubkey during deposit
        // setup which is used for reimbursements/cpfp.
        // so instead of sharing ones, we can just reuse this key (which is part of a taproot
        // address).
        let stake_signature = output_handles
            .s2_client
            .stakechain_wallet_signer()
            .sign_no_tweak(messages[1].as_ref())
            .await?;

        stake_tx.finalize(
            &prev_preimage,
            funds_signature,
            stake_signature,
            prev_connector_s,
        )
    };

    output_handles.tx_driver.drive(signed_stake_tx).await?;

    Ok(())
}

pub(super) async fn handle_withdrawal_fulfillment(
    cfg: ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    withdrawal_metadata: WithdrawalMetadata,
    user_descriptor: Descriptor,
) -> Result<(), ContractManagerErr> {
    let amount = cfg
        .pegout_graph_params
        .deposit_amount
        .checked_sub(cfg.pegout_graph_params.operator_fee)
        .unwrap_or_default();

    let withdrawal_fulfillment_tx =
        WithdrawalFulfillment::new(withdrawal_metadata, vec![], amount, None, user_descriptor);

    let mut wft_psbt = Psbt::from_unsigned_tx(withdrawal_fulfillment_tx.tx())
        .expect("withdrawal fulfillment transaction must be unsigned");

    let mut wallet = output_handles.wallet.write().await;

    info!("syncing wallet before finalizing withdrawal fulfillment tx");
    if let Err(err) = wallet.sync().await {
        error!(
            ?err,
            "could not sync wallet before finalizing withdrawal fulfillment tx"
        )
    };

    let general_wallet = wallet.general_wallet();

    match general_wallet.finalize_psbt(&mut wft_psbt, SignOptions::default()) {
        Ok(true) => {
            let signed_wft = wft_psbt.extract_tx().expect("must be signed by wallet");

            info!(
                txid = %signed_wft.compute_txid(),
                "submitting withdrawal fulfillment tx to the tx driver"
            );

            output_handles
                .tx_driver
                .drive(signed_wft)
                .await
                .map_err(|e| ContractManagerErr::FatalErr(Box::new(e)))?;
        }
        // in most cases, the other cases just mean that the wallet does not have enough
        // funds, in which case, there is nothing much we can do
        // but at the same time, we must not crash the node.
        Ok(false) => {
            error!("could not finalize withdrawal fulfillment transaction with general wallet");
        }
        Err(err) => {
            error!(%err, "could not sign withdrawal fulfillment with general wallet")
        }
    }

    Ok(())
}

/// Constructs, finalizes and broadcasts the claim transaction.
pub(super) async fn handle_publish_claim(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    stake_txid: Txid,
    deposit_txid: Txid,
    withdrawal_fulfillment_txid: Txid,
) -> Result<(), ContractManagerErr> {
    let pov_idx = cfg.operator_table.pov_idx();

    // the input to the claim transaction is the input to the stake transaction minus the two dust
    // outputs in the stake transaction.
    let input_amount = OPERATOR_FUNDS
        .checked_sub(SEGWIT_MIN_AMOUNT * 2)
        .unwrap_or_default();

    let claim_data = ClaimData {
        stake_outpoint: OutPoint::new(stake_txid, STAKE_VOUT),
        deposit_txid,
        input_amount,
    };

    let wots_client = output_handles.s2_client.wots_signer();

    let OutPoint {
        txid: prestake_txid,
        vout: prestake_vout,
    } = output_handles.db.get_pre_stake(pov_idx).await?.ok_or(
        StakeChainErr::StakeSetupDataNotFound(cfg.operator_table.pov_op_key().clone()),
    )?;

    let withdrawal_fulfillment_pk = wots_client
        .get_256_public_key(prestake_txid, prestake_vout, WITHDRAWAL_FULFILLMENT_PK_IDX)
        .await?;
    let withdrawal_fulfillment_pk =
        Wots256PublicKey::from_flattened_bytes(&withdrawal_fulfillment_pk).into();

    let network = cfg.network;
    let n_of_n_agg_pubkey = cfg
        .operator_table
        .tx_build_context(network)
        .aggregated_pubkey();

    let cpfp_key = output_handles
        .s2_client
        .general_wallet_signer()
        .pubkey()
        .await?;

    let connector_k = ConnectorK::new(network, withdrawal_fulfillment_pk);
    let connector_c0 = ConnectorC0::new(
        n_of_n_agg_pubkey,
        network,
        cfg.connector_params.pre_assert_timelock,
    );
    let connector_c1 = ConnectorC1::new(
        n_of_n_agg_pubkey,
        network,
        cfg.connector_params.payout_optimistic_timelock,
    );
    let connector_n_of_n = ConnectorNOfN::new(n_of_n_agg_pubkey, network);
    let connector_cpfp = ConnectorCpfp::new(cpfp_key, network);

    let claim_tx = ClaimTx::new(
        claim_data,
        connector_k,
        connector_c0,
        connector_c1,
        connector_n_of_n,
        connector_cpfp,
    );

    let wots_signature = wots_client
        .get_256_signature(
            prestake_txid,
            prestake_vout,
            WITHDRAWAL_FULFILLMENT_PK_IDX,
            &withdrawal_fulfillment_txid.to_byte_array(),
        )
        .await?;

    let signed_claim_tx = claim_tx.finalize(wots_signature);

    output_handles.tx_driver.drive(signed_claim_tx).await?;

    Ok(())
}
