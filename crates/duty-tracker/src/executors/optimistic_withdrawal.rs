//! Handles the withdrawal duty as it pertains to the optimistic case i.e., when no challenges
//! occur.

use std::sync::Arc;

use alpen_bridge_params::prelude::StakeChainParams;
use bdk_wallet::{miniscript::ToPublicKey, SignOptions};
use bitcoin::{
    hashes::{sha256, Hash},
    OutPoint, Psbt, Txid,
};
use bitcoin_bosd::Descriptor;
use secret_service_proto::v1::traits::*;
use strata_bridge_connectors::prelude::{
    ConnectorC0, ConnectorC1, ConnectorCpfp, ConnectorK, ConnectorNOfN, ConnectorP, ConnectorStake,
};
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{build_context::BuildContext, constants::SEGWIT_MIN_AMOUNT};
use strata_bridge_stake_chain::prelude::{StakeTx, OPERATOR_FUNDS, STAKE_VOUT};
use strata_bridge_tx_graph::{
    errors::TxGraphError,
    transactions::{
        claim::{ClaimData, ClaimTx},
        prelude::{
            CovenantTx, PayoutOptimisticData, PayoutOptimisticTx, WithdrawalFulfillment,
            WithdrawalMetadata,
        },
    },
};
use strata_p2p_types::Wots256PublicKey;
use tracing::{error, info};

use crate::{
    constants::WITHDRAWAL_FULFILLMENT_PK_IDX,
    contract_manager::{ExecutionConfig, OutputHandles},
    errors::{ContractManagerErr, StakeChainErr},
    s2_session_manager::MusigSessionManager,
};

/// Advances the stake chain by submitting the given transaction to the tx driver.
///
/// It is the responsibility of the caller to ensure that the supplied `stake_index` corresponds to
/// the provided `stake_tx`.
pub(crate) async fn handle_advance_stake_chain(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    stake_index: u32,
    stake_tx: StakeTx,
) -> Result<(), ContractManagerErr> {
    let operator_id = cfg.operator_table.pov_idx();
    let op_p2p_key = cfg.operator_table.pov_op_key();

    let MusigSessionManager { s2_client, .. } = &output_handles.s2_session_manager;

    let pre_stake_outpoint = output_handles
        .db
        .get_pre_stake(operator_id)
        .await?
        .ok_or(StakeChainErr::StakeSetupDataNotFound(op_p2p_key.clone()))?;

    let messages = stake_tx.sighashes();
    let funds_signature = s2_client
        .general_wallet_signer()
        .sign(messages[0].as_ref(), None)
        .await?;

    let signed_stake_tx = if stake_index == 0 {
        // the first stake transaction spends the pre-stake which is locked by the key in the
        // stake-chain wallet
        let stake_signature = s2_client
            .general_wallet_signer()
            .sign(messages[1].as_ref(), None)
            .await?;

        stake_tx.finalize_initial(funds_signature, stake_signature)
    } else {
        let pre_image_client = s2_client.stake_chain_preimages();
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
        let operator_pubkey = s2_client
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
        let stake_signature = s2_client
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

/// Constructs, finalizes and broadcasts the Withdrawal Fulfillment Transaction.
pub(crate) async fn handle_withdrawal_fulfillment(
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

/// Constructs, finalizes and broadcasts the Claim Transaction.
pub(crate) async fn handle_publish_claim(
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

    let MusigSessionManager { s2_client, .. } = &output_handles.s2_session_manager;

    let wots_client = s2_client.wots_signer();

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

/// Constructs, finalizes and broadcasts the Payout Optimistic Transaction.
pub(crate) async fn handle_publish_payout_optimistic(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    deposit_txid: Txid,
    claim_txid: Txid,
    stake_txid: Txid,
    stake_index: u32,
) -> Result<(), ContractManagerErr> {
    const DUST_OUTPUTS_IN_STAKE_TX: u64 = 2;
    const DUST_OUTPUTS_IN_CLAIM_TX: u64 = 3;

    let input_amount = OPERATOR_FUNDS
        .checked_sub(SEGWIT_MIN_AMOUNT * (DUST_OUTPUTS_IN_CLAIM_TX + DUST_OUTPUTS_IN_STAKE_TX))
        .unwrap_or_default();

    let MusigSessionManager { s2_client, .. } = &output_handles.s2_session_manager;

    let operator_key = s2_client.general_wallet_signer().pubkey().await?;
    let network = cfg.network;

    let payout_optimistic_data = PayoutOptimisticData {
        claim_txid,
        deposit_txid,
        stake_outpoint: OutPoint::new(stake_txid, STAKE_VOUT),
        input_amount,
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

    let pov_idx = cfg.operator_table.pov_idx();

    const DEPOSIT_INPUT_INDEX: u32 = 0;
    const C0_INPUT_INDEX: u32 = 1;
    const C1_INPUT_INDEX: u32 = 2;
    const N_OF_N_INPUT_INDEX: u32 = 3;
    const HASHLOCK_INPUT_INDEX: u32 = 4;

    let deposit_sig = output_handles
        .db
        .get_signature(pov_idx, payout_optimistic_txid, DEPOSIT_INPUT_INDEX)
        .await?
        .ok_or(TxGraphError::MissingNOfNSignature(
            pov_idx,
            payout_optimistic_txid,
            DEPOSIT_INPUT_INDEX,
        ))?;
    let c0_sig = output_handles
        .db
        .get_signature(pov_idx, payout_optimistic_txid, C0_INPUT_INDEX)
        .await?
        .ok_or(TxGraphError::MissingNOfNSignature(
            pov_idx,
            payout_optimistic_txid,
            C0_INPUT_INDEX,
        ))?;
    let c1_sig = output_handles
        .db
        .get_signature(pov_idx, payout_optimistic_txid, C1_INPUT_INDEX)
        .await?
        .ok_or(TxGraphError::MissingNOfNSignature(
            pov_idx,
            payout_optimistic_txid,
            C1_INPUT_INDEX,
        ))?;
    let n_of_n_sig = output_handles
        .db
        .get_signature(pov_idx, payout_optimistic_txid, N_OF_N_INPUT_INDEX)
        .await?
        .ok_or(TxGraphError::MissingNOfNSignature(
            pov_idx,
            payout_optimistic_txid,
            N_OF_N_INPUT_INDEX,
        ))?;
    let hashlock_sig = output_handles
        .db
        .get_signature(pov_idx, payout_optimistic_txid, HASHLOCK_INPUT_INDEX)
        .await?
        .ok_or(TxGraphError::MissingNOfNSignature(
            pov_idx,
            payout_optimistic_txid,
            HASHLOCK_INPUT_INDEX,
        ))?;

    let signed_payout_optimistic_tx =
        payout_optimistic_tx.finalize([deposit_sig, c0_sig, c1_sig, n_of_n_sig, hashlock_sig]);

    info!(txid = %payout_optimistic_txid, "submitting payout optimistic tx to the tx driver");
    output_handles
        .tx_driver
        .drive(signed_payout_optimistic_tx)
        .await?;

    Ok(())
}
