//! Handles the withdrawal duty as it pertains to the optimistic case i.e., when no challenges
//! occur.

use std::sync::Arc;

use algebra::retry::{retry_with, RetryAction, Strategy};
use bitcoin::{
    hashes::{sha256, Hash},
    sighash::{Prevouts, SighashCache},
    taproot, FeeRate, OutPoint, TapSighashType, Txid,
};
use bitcoin_bosd::Descriptor;
use bitcoind_async_client::traits::Reader;
use btc_tracker::{event::TxStatus, tx_driver::DriveErr};
use secret_service_proto::v2::traits::*;
use strata_bridge_connectors::prelude::{
    ConnectorC0, ConnectorC1, ConnectorCpfp, ConnectorK, ConnectorNOfN, ConnectorP, ConnectorStake,
};
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{
    build_context::BuildContext,
    scripts::taproot::{create_message_hash, TaprootWitness},
    types::BitcoinBlockHeight,
};
use strata_bridge_stake_chain::{
    prelude::{StakeTx, PAYOUT_VOUT, WITHDRAWAL_FULFILLMENT_VOUT},
    transactions::stake::{Head, StakeTxKind, Tail},
};
use strata_bridge_tx_graph::transactions::{
    claim::{ClaimData, ClaimTx},
    prelude::{
        CovenantTx, PayoutOptimisticData, PayoutOptimisticTx, WithdrawalMetadata,
        NUM_PAYOUT_OPTIMISTIC_INPUTS,
    },
};
use tracing::{debug, error, info, warn};

use crate::{
    contract_manager::{ExecutionConfig, OutputHandles},
    errors::{ContractManagerErr, StakeChainErr},
    executors::{
        config::StakeTxRetryConfig,
        constants::{DEPOSIT_VOUT, WITHDRAWAL_FULFILLMENT_PK_IDX},
        wots_handler::get_withdrawal_fulfillment_wots_pk,
    },
};

pub(crate) async fn handle_publish_first_stake(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    stake_tx: StakeTx<Head>,
) -> Result<(), ContractManagerErr> {
    info!("starting to publish first stake tx");

    // the first stake transaction spends the pre-stake which is locked by the key in the
    // stake-chain wallet
    let messages = stake_tx.sighashes(
        cfg.stake_chain_params.stake_amount,
        [
            cfg.funding_address.script_pubkey(),
            cfg.pre_stake_pubkey.clone(),
        ],
    );

    let funds_signature = output_handles
        .s2_client
        .stakechain_wallet_signer()
        .sign(messages[0].as_ref(), None)
        .await?;
    let stake_signature = output_handles
        .s2_client
        .stakechain_wallet_signer()
        .sign(messages[1].as_ref(), None)
        .await?;

    let signed_stake_tx = stake_tx.finalize_unchecked(funds_signature, stake_signature);

    info!(txid=%signed_stake_tx.compute_txid(), "broadcasting first stake transaction");

    try_publish_stake_tx(
        output_handles,
        cfg.stake_tx_retry_config,
        signed_stake_tx,
        0,
    )
    .await
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

    let messages = stake_tx.sighashes(cfg.funding_address.script_pubkey());

    let funds_signature = output_handles
        .s2_client
        .stakechain_wallet_signer()
        .sign(messages[0].as_ref(), None)
        .await?;

    // all the stake transactions except the first one are locked with the general wallet
    // signer.
    // this is a caveat of the fact that we only share one x-only pubkey during deposit
    // setup which is used for reimbursements/cpfp.
    // so instead of sharing another key, we can just reuse this key (which is part of a taproot
    // address).
    let stake_signature = output_handles
        .s2_client
        .general_wallet_signer()
        .sign_no_tweak(messages[1].as_ref())
        .await?;

    let operator_id = cfg.operator_table.pov_idx();
    let op_p2p_key = cfg.operator_table.pov_p2p_key();

    let pre_stake_outpoint = output_handles
        .db
        .get_pre_stake(operator_id)
        .await?
        .ok_or(StakeChainErr::StakeSetupDataNotFound(op_p2p_key.clone()))?;

    let OutPoint {
        txid: pre_stake_txid,
        vout: pre_stake_vout,
    } = pre_stake_outpoint;

    let pre_image_client = output_handles.s2_client.stake_chain_preimages();
    let prev_preimage = pre_image_client
        .get_preimg(pre_stake_txid, pre_stake_vout, stake_index - 1)
        .await?;
    let prev_stake_hash = sha256::Hash::hash(&prev_preimage);

    let n_of_n_agg_pubkey = cfg
        .operator_table
        .tx_build_context(cfg.network)
        .aggregated_pubkey();

    let operator_pubkey = output_handles
        .s2_client
        .general_wallet_signer()
        .pubkey()
        .await?;

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
    try_publish_stake_tx(
        output_handles,
        cfg.stake_tx_retry_config,
        signed_stake_tx,
        stake_index,
    )
    .await
}

/// Tries to publish the stake transaction using the provided `OutputHandles` with retry logic.
///
/// # Errors
///
/// If the transaction fails to be broadcasted after maximum retries or on fatal errors.
// HACK: (@Rajil1213) this function is a workaround for the fact that the stake chain must be
// broadcasted sequentially with a certain timelock between consecutive links.
// If there are multiple withdrawal requests, it may be the case that the transactions cannot be
// broadcasted concurrently, so we retry until the parent transaction is confirmed or the maximum
// number of retries is reached.
async fn try_publish_stake_tx(
    output_handles: Arc<OutputHandles>,
    retry_config: StakeTxRetryConfig,
    signed_stake_tx: bitcoin::Transaction,
    stake_index: u32,
) -> Result<(), ContractManagerErr> {
    // NOTE: (@Rajil1213) The following constants are not made configurable as this is supposed to
    // be a temporary workaround.

    let stake_txid = signed_stake_tx.compute_txid();

    // Create a retry strategy that handles different error types appropriately
    let strategy = Strategy::new(move |error: &ContractManagerErr, attempt| {
        match error {
            ContractManagerErr::TxDriverErr(DriveErr::DriverAborted) => {
                // Fatal error - don't retry
                error!(?error, %stake_txid, %stake_index, "fatal error: driver aborted, not retrying");
                RetryAction::Stop
            }
            ContractManagerErr::TxDriverErr(DriveErr::PublishFailed(ref err)) => {
                // Retryable error
                warn!(
                    %err,
                    %stake_txid,
                    %stake_index,
                    %attempt,
                    "failed to broadcast stake transaction, will retry..."
                );
                RetryAction::Retry(retry_config.retry_delay)
            }
            _ => {
                // Other errors are considered fatal
                error!(?error, %stake_txid, %stake_index, "unexpected error type, not retrying");
                RetryAction::Stop
            }
        }
    })
    .with_max_retries(retry_config.max_retries as usize);

    retry_with(strategy, move || {
        let output_handles = output_handles.clone();
        let signed_stake_tx = signed_stake_tx.clone();
        async move {
            match output_handles
                .tx_driver
                .drive(signed_stake_tx, TxStatus::is_buried)
                .await
            {
                Ok(_) => {
                    debug!(%stake_txid, %stake_index, "successfully broadcasted stake transaction");
                    Ok(())
                }
                Err(tx_driver_err) => Err(ContractManagerErr::TxDriverErr(tx_driver_err)),
            }
        }
    })
    .await
}

/// Constructs, finalizes and broadcasts the Withdrawal Fulfillment Transaction.
pub(crate) async fn handle_withdrawal_fulfillment(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    stake_tx: StakeTxKind,
    withdrawal_metadata: WithdrawalMetadata,
    user_descriptor: Descriptor,
    deadline: BitcoinBlockHeight,
) -> Result<(), ContractManagerErr> {
    let deposit_idx = withdrawal_metadata.deposit_idx;
    info!(dest=%user_descriptor, %deposit_idx, %deadline, "handling duty to fulfill withdrawal");

    match stake_tx {
        StakeTxKind::Head(stake_tx) => {
            handle_publish_first_stake(cfg, output_handles.clone(), stake_tx).await?
        }
        StakeTxKind::Tail(stake_tx) => {
            handle_advance_stake_chain(
                cfg,
                output_handles.clone(),
                withdrawal_metadata.deposit_idx,
                stake_tx,
            )
            .await?
        }
    }

    let pov_idx = cfg.operator_table.pov_idx();
    let assignee = withdrawal_metadata.operator_idx;
    let is_assigned_to_me = assignee == pov_idx;

    if !is_assigned_to_me {
        debug!(%pov_idx, %assignee, "not fronting withdrawal as it is not assigned to me");
        return Ok(());
    }

    fulfill_withdrawal(
        cfg,
        &output_handles,
        withdrawal_metadata,
        user_descriptor,
        deadline,
    )
    .await?;

    Ok(())
}

async fn fulfill_withdrawal(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    withdrawal_metadata: WithdrawalMetadata,
    user_descriptor: Descriptor,
    deadline: BitcoinBlockHeight,
) -> Result<(), ContractManagerErr> {
    let fulfillment_window = cfg.min_withdrawal_fulfillment_window;
    let cur_height = output_handles
        .bitcoind_rpc_client
        .get_blockchain_info()
        .await
        .map_err(|e| {
            // this means we cannot be sure whether the deadline has been reached or not
            // so we do not proceed with the duty execution to be on the safe side.
            error!(?e, "failed to get current blockchain height");

            ContractManagerErr::BitcoinCoreRPCErr(e)
        })?
        .blocks;

    let reached_deadline = cur_height >= deadline.saturating_sub(fulfillment_window);
    if reached_deadline {
        warn!(%cur_height, %deadline, %fulfillment_window, "current height is more than the deadline minus the fulfillment window, skipping withdrawal fulfillment");
        return Ok(());
    }

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

    // acquire the wallet lock to ensure that we are not using spent outputs
    // then drop it immediately once we have the withdrawal fulfillment psbt constructed.
    let wft_psbt = {
        let mut wallet = output_handles.wallet.write().await;

        // this is to make sure that we're not using spent outputs
        // if we are, the duty will not be fulfilled and we'll just wait for the next assigned
        // operator to fulfill the duty.
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
            Ok(wft_psbt) => wft_psbt,
            Err(err) => {
                // most of the time, this just means that the wallet does not have enough funds
                error!(%err, "could not front withdrawal");

                return Ok(());
            }
        }
    };

    let txid = wft_psbt.unsigned_tx.compute_txid();
    info!(%txid, "signing withdrawal fulfillment transaction");
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
            .s2_client
            .general_wallet_signer()
            .sign(msg.as_ref(), None)
            .await?;

        signed_wft.input[input_index]
            .witness
            .push(signature.serialize());
    }

    info!(%txid, "submitting withdrawal fulfillment tx to the tx driver");

    output_handles
        .tx_driver
        .drive(signed_wft, TxStatus::is_buried)
        .await?;

    Ok(())
}

/// Constructs, finalizes and broadcasts the Claim Transaction.
pub(crate) async fn handle_publish_claim(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    stake_txid: Txid,
    deposit_txid: Txid,
    withdrawal_fulfillment_txid: Txid,
) -> Result<(), ContractManagerErr> {
    info!(%deposit_txid, %withdrawal_fulfillment_txid, "executing duty to publish claim transaction");

    let claim_data = ClaimData {
        stake_outpoint: OutPoint::new(stake_txid, WITHDRAWAL_FULFILLMENT_VOUT),
        deposit_txid,
    };

    let wots_client = output_handles.s2_client.wots_signer();

    let withdrawal_fulfillment_pk =
        get_withdrawal_fulfillment_wots_pk(deposit_txid, &wots_client).await?;

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

    let connector_k = ConnectorK::new(network, withdrawal_fulfillment_pk.into());
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
    let connector_cpfp = ConnectorCpfp::new(cpfp_key.into(), network);

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
    output_handles
        .tx_driver
        .drive(signed_claim_tx, TxStatus::is_buried)
        .await?;

    Ok(())
}

/// Constructs, finalizes and broadcasts the Payout Optimistic Transaction.
pub(crate) async fn handle_publish_payout_optimistic(
    cfg: &ExecutionConfig,
    output_handles: &OutputHandles,
    deposit_txid: Txid,
    claim_txid: Txid,
    stake_txid: Txid,
    stake_index: u32,
    agg_sigs: [taproot::Signature; NUM_PAYOUT_OPTIMISTIC_INPUTS],
) -> Result<(), ContractManagerErr> {
    let operator_key = output_handles
        .s2_client
        .general_wallet_signer()
        .pubkey()
        .await?;
    let network = cfg.network;

    let payout_optimistic_data = PayoutOptimisticData {
        claim_txid,
        deposit_txid,
        stake_outpoint: OutPoint::new(stake_txid, PAYOUT_VOUT),
        deposit_amount: cfg.pegout_graph_params.deposit_amount,
        operator_descriptor: operator_key.into(),
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
            cfg.operator_table.pov_p2p_key().clone(),
        ))?;

    let stake_hash = output_handles
        .s2_client
        .stake_chain_preimages()
        .get_preimg(prestake_txid, prestake_vout, stake_index)
        .await?;
    let stake_hash = sha256::Hash::hash(&stake_hash);

    let connector_p = ConnectorP::new(n_of_n_agg_pubkey, stake_hash, network);

    let connector_cpfp = ConnectorCpfp::new(operator_key.into(), network);

    let payout_optimistic_tx = PayoutOptimisticTx::new(
        payout_optimistic_data,
        connector_c0,
        connector_c1,
        connector_n_of_n,
        connector_p,
        connector_cpfp,
    )?;
    let payout_optimistic_txid = payout_optimistic_tx.compute_txid();

    let signed_payout_optimistic_tx =
        payout_optimistic_tx.finalize(agg_sigs.map(|agg_sig| agg_sig.signature));

    info!(txid = %payout_optimistic_txid, "submitting payout optimistic tx to the tx driver");
    output_handles
        .tx_driver
        .drive(signed_payout_optimistic_tx, TxStatus::is_buried)
        .await?;

    Ok(())
}
