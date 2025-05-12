//! Handles the withdrawal duty as it pertains to the optimistic case i.e., when no challenges
//! occur.

use std::sync::Arc;

use bitcoin::{
    hashes::{sha256, Hash},
    sighash::{Prevouts, SighashCache},
    FeeRate, OutPoint, TapSighashType, Txid,
};
use bitcoin_bosd::Descriptor;
use bitcoind_async_client::traits::Reader;
use musig2::PartialSignature;
use secp256k1::schnorr::Signature;
use secret_service_proto::v1::traits::*;
use strata_bridge_connectors::prelude::{
    ConnectorC0, ConnectorC1, ConnectorCpfp, ConnectorK, ConnectorNOfN, ConnectorP, ConnectorStake,
};
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{
    build_context::BuildContext,
    scripts::taproot::{create_message_hash, TaprootWitness},
};
use strata_bridge_stake_chain::{
    prelude::{StakeTx, PAYOUT_VOUT, WITHDRAWAL_FULFILLMENT_VOUT},
    transactions::stake::{Head, Tail},
};
use strata_bridge_tx_graph::transactions::{
    claim::{ClaimData, ClaimTx},
    prelude::{
        CovenantTx, PayoutOptimisticData, PayoutOptimisticTx, WithdrawalMetadata,
        NUM_PAYOUT_OPTIMISTIC_INPUTS,
    },
};
use strata_p2p_types::Wots256PublicKey;
use tracing::{error, info, warn};

use crate::{
    contract_manager::{ExecutionConfig, OutputHandles},
    errors::{ContractManagerErr, StakeChainErr},
    executors::constants::{DEPOSIT_VOUT, WITHDRAWAL_FULFILLMENT_PK_IDX},
    s2_session_manager::MusigSessionManager,
};

pub(crate) async fn handle_publish_first_stake(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    stake_tx: StakeTx<Head>,
) -> Result<(), ContractManagerErr> {
    info!("starting to publish first stake tx");

    let MusigSessionManager { s2_client, .. } = &output_handles.s2_session_manager;

    // the first stake transaction spends the pre-stake which is locked by the key in the
    // stake-chain wallet
    let messages = stake_tx.sighashes(
        cfg.stake_chain_params.stake_amount,
        [
            cfg.funding_address.script_pubkey(),
            cfg.pre_stake_pubkey.clone(),
        ],
    );

    let funds_signature = s2_client
        .stakechain_wallet_signer()
        .sign(messages[0].as_ref(), None)
        .await?;
    let stake_signature = s2_client
        .stakechain_wallet_signer()
        .sign(messages[1].as_ref(), None)
        .await?;

    let signed_stake_tx = stake_tx.finalize_unchecked(funds_signature, stake_signature);

    info!(txid=%signed_stake_tx.compute_txid(), "broadcasting first stake transaction");
    output_handles.tx_driver.drive(signed_stake_tx).await?;

    Ok(())
}

/// Advances the stake chain by submitting the given transaction to the tx driver.
///
/// It is the responsibility of the caller to ensure that the supplied `stake_index` corresponds to
/// the provided `stake_tx`.
pub(crate) async fn handle_advance_stake_chain(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    stake_index: u32,
    stake_tx: StakeTx<Tail>,
) -> Result<(), ContractManagerErr> {
    info!(%stake_index, "starting to advance stake chain");

    let MusigSessionManager { s2_client, .. } = &output_handles.s2_session_manager;

    let messages = stake_tx.sighashes(cfg.funding_address.script_pubkey());

    let funds_signature = s2_client
        .stakechain_wallet_signer()
        .sign(messages[0].as_ref(), None)
        .await?;

    // all the stake transactions except the first one are locked with the general wallet
    // signer.
    // this is a caveat of the fact that we only share one x-only pubkey during deposit
    // setup which is used for reimbursements/cpfp.
    // so instead of sharing another key, we can just reuse this key (which is part of a taproot
    // address).
    let stake_signature = s2_client
        .general_wallet_signer()
        .sign_no_tweak(messages[1].as_ref())
        .await?;

    let operator_id = cfg.operator_table.pov_idx();
    let op_p2p_key = cfg.operator_table.pov_op_key();

    let pre_stake_outpoint = output_handles
        .db
        .get_pre_stake(operator_id)
        .await?
        .ok_or(StakeChainErr::StakeSetupDataNotFound(op_p2p_key.clone()))?;

    let OutPoint {
        txid: pre_stake_txid,
        vout: pre_stake_vout,
    } = pre_stake_outpoint;

    let pre_image_client = s2_client.stake_chain_preimages();
    let prev_preimage = pre_image_client
        .get_preimg(pre_stake_txid, pre_stake_vout, stake_index - 1)
        .await?;
    let prev_stake_hash = sha256::Hash::hash(&prev_preimage);

    let n_of_n_agg_pubkey = cfg
        .operator_table
        .tx_build_context(cfg.network)
        .aggregated_pubkey();

    let operator_pubkey = s2_client.general_wallet_signer().pubkey().await?;

    let prev_connector_s = ConnectorStake::new(
        n_of_n_agg_pubkey,
        operator_pubkey,
        prev_stake_hash,
        cfg.stake_chain_params.delta,
        cfg.network,
    );

    let signed_stake_tx = stake_tx.finalize_unchecked(
        &prev_preimage,
        funds_signature,
        stake_signature,
        prev_connector_s,
    );

    info!(txid=%signed_stake_tx.compute_txid(), %stake_index, "broadcasting stake transaction");
    output_handles.tx_driver.drive(signed_stake_tx).await?;

    Ok(())
}

/// Constructs, finalizes and broadcasts the Withdrawal Fulfillment Transaction.
pub(crate) async fn handle_withdrawal_fulfillment(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    withdrawal_metadata: WithdrawalMetadata,
    user_descriptor: Descriptor,
) -> Result<(), ContractManagerErr> {
    info!(dest=%user_descriptor, deposit_idx=%withdrawal_metadata.deposit_idx, "fulfilling withdrawal");

    let amount = cfg
        .pegout_graph_params
        .deposit_amount
        .checked_sub(cfg.pegout_graph_params.operator_fee)
        .unwrap_or_default();

    let fee_rate = output_handles
        .bitcoind_rpc_client
        .estimate_smart_fee(1)
        .await
        .expect("should be able to get the fee rate estimate");
    let fee_rate = FeeRate::from_sat_per_vb(fee_rate).unwrap_or(FeeRate::DUST);

    let op_return_data = withdrawal_metadata.op_return_data();
    let user_script_pubkey = user_descriptor.to_script();

    let mut wallet = output_handles.wallet.write().await;

    // this is to make sure that we're not using spent outputs
    // if we are, the duty will not be fulfilled and we'll just wait for the next assigned operator
    // to fulfill the duty.
    info!("syncing wallet before constructing withdrawal fulfillment tx");
    if let Err(e) = wallet.sync().await {
        warn!(
            ?e,
            "could not sync wallet before constructing withdrawal tx, continuing anyway"
        );
    };

    match wallet.front_withdrawal(
        fee_rate,
        user_script_pubkey,
        amount,
        op_return_data.as_ref(),
    ) {
        Ok(wft_psbt) => {
            let mut sighash_cache = SighashCache::new(&wft_psbt.unsigned_tx);

            let prevouts = wft_psbt
                .inputs
                .iter()
                .filter_map(|input| input.witness_utxo.clone())
                .collect::<Vec<_>>();
            let prevouts = Prevouts::All(&prevouts);

            let message_hashes = wft_psbt.inputs.iter().enumerate().map(|(input_index, _)| {
                create_message_hash(
                    &mut sighash_cache,
                    prevouts.clone(),
                    &TaprootWitness::Key,
                    TapSighashType::Default,
                    input_index,
                )
                .expect("must be able to create message hash for each input in wft")
            });

            let mut signed_wft = wft_psbt.unsigned_tx.clone();
            for (input_index, msg) in message_hashes.enumerate() {
                let signature = output_handles
                    .s2_session_manager
                    .s2_client
                    .general_wallet_signer()
                    .sign(msg.as_ref(), None)
                    .await?;

                signed_wft.input[input_index]
                    .witness
                    .push(signature.serialize());
            }

            info!(txid=%signed_wft.compute_txid(), "submitting withdrawal fulfillment tx to the tx driver");

            output_handles.tx_driver.drive(signed_wft).await?;
        }
        Err(err) => {
            // most of the time, this just means that the wallet does not have enough funds
            error!(%err, "could not front withdrawal");
        }
    }

    Ok(())
}

/// Constructs, finalizes and broadcasts the Claim Transaction.
pub(crate) async fn handle_publish_claim(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    stake_txid: Txid,
    deposit_txid: Txid,
    withdrawal_fulfillment_txid: Txid,
) -> Result<(), ContractManagerErr> {
    info!(%deposit_txid, %withdrawal_fulfillment_txid, "executing duty to publish claim transaction");

    let claim_data = ClaimData {
        stake_outpoint: OutPoint::new(stake_txid, WITHDRAWAL_FULFILLMENT_VOUT),
        deposit_txid,
    };

    let MusigSessionManager { s2_client, .. } = &output_handles.s2_session_manager;

    let wots_client = s2_client.wots_signer();

    let withdrawal_fulfillment_pk = wots_client
        .get_256_public_key(deposit_txid, DEPOSIT_VOUT, WITHDRAWAL_FULFILLMENT_PK_IDX)
        .await?;
    let withdrawal_fulfillment_pk =
        Wots256PublicKey::from_flattened_bytes(&withdrawal_fulfillment_pk).into();

    let network = cfg.network;
    let n_of_n_agg_pubkey = cfg
        .operator_table
        .tx_build_context(network)
        .aggregated_pubkey();

    let cpfp_key = s2_client.general_wallet_signer().pubkey().await?;

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
            deposit_txid,
            DEPOSIT_VOUT,
            WITHDRAWAL_FULFILLMENT_PK_IDX,
            &withdrawal_fulfillment_txid.to_byte_array(),
        )
        .await?;

    let signed_claim_tx = claim_tx.finalize(wots_signature);

    info!(claim_txid=%signed_claim_tx.compute_txid(), %deposit_txid, "broadcasting claim transaction");
    output_handles.tx_driver.drive(signed_claim_tx).await?;

    Ok(())
}

/// Constructs, finalizes and broadcasts the Payout Optimistic Transaction.
pub(crate) async fn handle_publish_payout_optimistic(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    deposit_txid: Txid,
    claim_txid: Txid,
    stake_txid: Txid,
    stake_index: u32,
    partials: [Vec<PartialSignature>; NUM_PAYOUT_OPTIMISTIC_INPUTS],
) -> Result<(), ContractManagerErr> {
    let MusigSessionManager { s2_client, .. } = &output_handles.s2_session_manager;

    let operator_key = s2_client.general_wallet_signer().pubkey().await?;
    let network = cfg.network;

    let payout_optimistic_data = PayoutOptimisticData {
        claim_txid,
        deposit_txid,
        stake_outpoint: OutPoint::new(stake_txid, PAYOUT_VOUT),
        deposit_amount: cfg.pegout_graph_params.deposit_amount,
        operator_key,
        network,
    };

    let n_of_n_agg_pubkey = cfg
        .operator_table
        .tx_build_context(cfg.network)
        .aggregated_pubkey();

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

    let OutPoint {
        txid: prestake_txid,
        vout: prestake_vout,
    } = output_handles
        .db
        .get_pre_stake(cfg.operator_table.pov_idx())
        .await?
        .ok_or(StakeChainErr::StakeSetupDataNotFound(
            cfg.operator_table.pov_op_key().clone(),
        ))?;

    let stake_hash = s2_client
        .stake_chain_preimages()
        .get_preimg(prestake_txid, prestake_vout, stake_index)
        .await?;
    let stake_hash = sha256::Hash::hash(&stake_hash);

    let connector_p = ConnectorP::new(n_of_n_agg_pubkey, stake_hash, network);

    let connector_cpfp = ConnectorCpfp::new(operator_key, network);

    let payout_optimistic_tx = PayoutOptimisticTx::new(
        payout_optimistic_data,
        connector_c0,
        connector_c1,
        connector_n_of_n,
        connector_p,
        connector_cpfp,
    );
    let payout_optimistic_txid = payout_optimistic_tx.compute_txid();

    let mut signatures = Vec::with_capacity(partials.len());

    for (input_index, partials_per_op) in partials.iter().enumerate() {
        let outpoint = OutPoint::new(payout_optimistic_txid, input_index as u32);

        for (op_idx, partial) in partials_per_op.iter().enumerate() {
            let sender = cfg
                .operator_table
                .idx_to_btc_key(&(op_idx as u32))
                .expect("operator index must exist in the table");

            // FIXME: (@Rajil1213) this call may fail if the s2 server crashed between the time the
            // session was created and the time this call is made. One way to get the aggregate
            // signature and then store that in the database/state instead of aggregating them just
            // in time.
            output_handles
                .s2_session_manager
                .put_partial(outpoint, sender.x_only_public_key().0, *partial)
                .await?;
        }

        let signature = output_handles
            .s2_session_manager
            .get_signature(outpoint)
            .await?;

        let signature =
            Signature::from_slice(&signature.serialize()[..]).expect("must have the right size");

        signatures.push(signature);
    }

    let signed_payout_optimistic_tx =
        payout_optimistic_tx.finalize(signatures.try_into().expect("must have the right size"));

    info!(txid = %payout_optimistic_txid, "submitting payout optimistic tx to the tx driver");
    output_handles
        .tx_driver
        .drive(signed_payout_optimistic_tx)
        .await?;

    Ok(())
}
