use std::sync::Arc;

use bitcoin::{taproot, Network, OutPoint, Txid};
use bitvm::chunk::api::generate_assertions;
use btc_notify::client::TxStatus;
use futures::future::join_all;
use rand::thread_rng;
use secp256k1::rand::{self, Rng};
use secret_service_proto::v1::traits::*;
use strata_bridge_connectors::prelude::{
    ConnectorA256Factory, ConnectorA3, ConnectorAHashFactory, ConnectorC0, ConnectorCpfp,
    ConnectorNOfN, ConnectorP,
};
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{constants::NUM_ASSERT_DATA_TX, wots::Assertions};
use strata_bridge_proof_snark::bridge_vk;
use strata_bridge_stake_chain::prelude::PAYOUT_VOUT as STAKE_TO_PAYOUT_VOUT;
use strata_bridge_tx_graph::transactions::{
    claim::PAYOUT_VOUT as CLAIM_TO_PAYOUT_VOUT,
    payout::{PayoutData, PayoutTx, NUM_PAYOUT_INPUTS},
    prelude::{
        AssertDataTxBatch, AssertDataTxInput, CovenantTx, PostAssertTx, PostAssertTxData,
        PreAssertData, PreAssertTx,
    },
};
use strata_p2p_types::WotsPublicKeys;
use tracing::{info, warn};

use crate::{
    contract_manager::{ExecutionConfig, OutputHandles},
    contract_state_machine::TransitionErr,
    errors::{ContractManagerErr, StakeChainErr},
    executors::{
        proof_handler::{generate_proof, prepare_proof_input},
        wots_handler::{get_wots_pks, sign_assertions},
    },
    s2_session_manager::MusigSessionManager,
};

pub(crate) async fn handle_publish_pre_assert(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    deposit_idx: u32,
    deposit_txid: Txid,
    claim_txid: Txid,
    agg_sig: taproot::Signature,
) -> Result<(), ContractManagerErr> {
    info!(%deposit_idx, %deposit_txid, %claim_txid, "executing duty to publish pre-assert tx");

    let MusigSessionManager { s2_client, .. } = &output_handles.s2_session_manager;

    let pre_assert_data = PreAssertData { claim_txid };

    let n_of_n_agg_key = cfg
        .operator_table
        .aggregated_btc_key()
        .x_only_public_key()
        .0;
    let network = cfg.network;
    let operator_key = s2_client.general_wallet_signer().pubkey().await?;

    let connector_c0 = ConnectorC0::new(
        n_of_n_agg_key,
        network,
        cfg.connector_params.pre_assert_timelock,
    );

    let connector_cpfp = ConnectorCpfp::new(operator_key, network);

    info!(%deposit_idx, %deposit_txid, "getting wots public keys from s2");
    let wots_pks = get_wots_pks(deposit_txid, s2_client).await?;

    let (connector_a256_factory, connector_a_hash_factory) =
        create_assert_data_connectors(network, wots_pks);

    info!(%deposit_idx, %deposit_txid, "constructing pre-assert transaction");
    let pre_assert_tx = PreAssertTx::new(
        pre_assert_data,
        connector_c0,
        connector_cpfp,
        connector_a256_factory,
        connector_a_hash_factory,
    );

    let signed_pre_assert_tx = pre_assert_tx.finalize(agg_sig.signature);
    info!(
        txid = %signed_pre_assert_tx.compute_txid(),
        "submitting pre-assert transaction to the tx-driver"
    );

    output_handles
        .tx_driver
        .drive(signed_pre_assert_tx, TxStatus::is_buried)
        .await?;

    Ok(())
}

pub(crate) async fn handle_publish_assert_data(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    deposit_idx: u32,
    deposit_txid: Txid,
    assert_data_input: AssertDataTxInput,
    withdrawal_fulfillment_txid: Txid,
    start_height: u64,
) -> Result<(), ContractManagerErr> {
    info!(%deposit_idx, %deposit_txid, %start_height, %withdrawal_fulfillment_txid, "preparing proof input");
    let input = prepare_proof_input(
        cfg,
        deposit_idx,
        output_handles.clone(),
        withdrawal_fulfillment_txid,
        start_height,
    )
    .await?;

    info!(header_length=%input.headers.len(), "generating proof");
    let (proof, scalars, public_params) = generate_proof(&input)?;

    let start_time = std::time::Instant::now();
    info!(%deposit_idx, %deposit_txid, estimated_time="5 mins", "generating assertions for proof, this will take time");
    let groth16_assertions = generate_assertions(
        proof,
        scalars.to_vec(),
        &bridge_vk::GROTH16_VERIFICATION_KEY,
    )
    .map_err(|e| TransitionErr(format!("could not generate assertions due to {e:?}")))?;
    info!(%deposit_idx, %deposit_txid, elapsed_time=?start_time.elapsed(), "assertions generated successfully");

    let mut assertions = Assertions {
        withdrawal_fulfillment: public_params.withdrawal_fulfillment_txid.0,
        groth16: groth16_assertions,
    };

    if cfg.is_faulty {
        warn!(action = "making a faulty assertion");
        for _ in 0..assertions.groth16.2.len() {
            let proof_index_to_tweak = thread_rng().gen_range(0..assertions.groth16.2.len());

            warn!(action = "introducing faulty assertion", index=%proof_index_to_tweak);
            if assertions.groth16.1[proof_index_to_tweak] != [0u8; 32] {
                assertions.groth16.1[proof_index_to_tweak] = [0u8; 32];
                break;
            }
        }
    }

    let agg_pubkey = cfg
        .operator_table
        .aggregated_btc_key()
        .x_only_public_key()
        .0;
    let connector_n_of_n = ConnectorNOfN::new(agg_pubkey, cfg.network);

    let general_key = output_handles
        .s2_session_manager
        .s2_client
        .general_wallet_signer()
        .pubkey()
        .await?;
    let connector_cpfp = ConnectorCpfp::new(general_key, cfg.network);

    let assert_data_tx_batch =
        AssertDataTxBatch::new(assert_data_input, connector_n_of_n, connector_cpfp);

    info!(%deposit_idx, %deposit_txid, "committing to assertions with WOTS");
    let MusigSessionManager { s2_client, .. } = &output_handles.s2_session_manager;
    let wots_client = s2_client.wots_signer();
    let wots_signatures = sign_assertions(deposit_txid, &wots_client, assertions).await?;

    info!(%deposit_txid, "finalizing assert-data transactions with signed assertions");
    let wots_pks = get_wots_pks(deposit_txid, s2_client).await?;

    let (connector_a256_factory, connector_a_hash_factory) =
        create_assert_data_connectors(cfg.network, wots_pks);

    let signed_assert_data_txs = assert_data_tx_batch.finalize(
        connector_a_hash_factory,
        connector_a256_factory,
        wots_signatures,
    );

    // submit assert-data txs to the tx-driver
    info!(%deposit_idx, %deposit_txid, total_txs=%signed_assert_data_txs.len(), "submitting assert-data transactions to the tx-driver");

    let assert_data_batch_broadcast_job =
        signed_assert_data_txs
            .into_iter()
            .enumerate()
            .map(|(index, signed_assert_data_tx)| {
                let txid = signed_assert_data_tx.compute_txid();
                info!(%txid, %index, "submitting assert-data transaction to the tx-driver");

                output_handles
                    .tx_driver
                    .drive(signed_assert_data_tx, TxStatus::is_mined)
            });

    join_all(assert_data_batch_broadcast_job)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    info!(%deposit_idx, %deposit_txid, "assert-data transactions submitted successfully");

    Ok(())
}

pub(crate) async fn handle_publish_post_assert(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    deposit_txid: Txid,
    assert_data_txids: [Txid; NUM_ASSERT_DATA_TX],
    agg_sigs: [taproot::Signature; NUM_ASSERT_DATA_TX],
) -> Result<(), ContractManagerErr> {
    info!(%deposit_txid, "executing duty to publish post-assert transaction");

    let post_assert_data = PostAssertTxData {
        assert_data_txids: assert_data_txids.to_vec(),
        deposit_txid,
    };
    let agg_key = cfg
        .operator_table
        .aggregated_btc_key()
        .x_only_public_key()
        .0;
    let connector_n_of_n = ConnectorNOfN::new(agg_key, cfg.network);

    let MusigSessionManager { s2_client, .. } = &output_handles.s2_session_manager;

    let general_key = s2_client.general_wallet_signer().pubkey().await?;
    let connector_cpfp = ConnectorCpfp::new(general_key, cfg.network);

    info!(%deposit_txid, "getting WOTS public keys from S2 for post-assert transaction");
    let wots_pks = get_wots_pks(deposit_txid, s2_client).await?;
    let connector_a3 = ConnectorA3::new(
        cfg.network,
        deposit_txid,
        agg_key,
        wots_pks.try_into().expect("must have the right size"),
        cfg.connector_params.payout_timelock,
    );

    let post_assert_tx = PostAssertTx::new(
        post_assert_data,
        connector_n_of_n,
        connector_a3,
        connector_cpfp,
    );

    info!(%deposit_txid, "finalizing post-assert transaction with aggregated signatures");
    let signed_post_assert_tx = post_assert_tx.finalize(&agg_sigs.map(|agg_sig| agg_sig.signature));
    let txid = signed_post_assert_tx.compute_txid();

    info!(%deposit_txid, %txid, "submitting post-assert transaction to the tx-driver");
    output_handles
        .tx_driver
        .drive(signed_post_assert_tx, TxStatus::is_buried)
        .await?;

    Ok(())
}

#[expect(clippy::too_many_arguments)]
pub(crate) async fn handle_publish_payout(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    deposit_idx: u32,
    deposit_txid: Txid,
    stake_txid: Txid,
    claim_txid: Txid,
    post_assert_txid: Txid,
    agg_sigs: [taproot::Signature; NUM_PAYOUT_INPUTS],
) -> Result<(), ContractManagerErr> {
    info!(%deposit_idx, %deposit_txid, %claim_txid, %stake_txid, %post_assert_txid, "executing duty to publish payout transaction");
    let MusigSessionManager { s2_client, .. } = &output_handles.s2_session_manager;

    let reimbursement_key = s2_client.general_wallet_signer().pubkey().await?;

    let payout_data = PayoutData {
        post_assert_txid,
        deposit_txid,
        claim_outpoint: OutPoint::new(claim_txid, CLAIM_TO_PAYOUT_VOUT),
        stake_outpoint: OutPoint::new(stake_txid, STAKE_TO_PAYOUT_VOUT),
        deposit_amount: cfg.pegout_graph_params.deposit_amount,
        operator_key: reimbursement_key,
        network: cfg.network,
    };

    let agg_key = cfg
        .operator_table
        .aggregated_btc_key()
        .x_only_public_key()
        .0;
    let connector_n_of_n = ConnectorNOfN::new(agg_key, cfg.network);

    info!("querying S2 for wots pks");
    let wots_pks = get_wots_pks(deposit_txid, s2_client).await?;
    let connector_a3 = ConnectorA3::new(
        cfg.network,
        deposit_txid,
        agg_key,
        wots_pks.try_into().expect("must have the right size"),
        cfg.connector_params.payout_timelock,
    );

    let pov_idx = cfg.operator_table.pov_idx();
    let stake_data = output_handles
        .db
        .get_stake_data(pov_idx, deposit_idx)
        .await?
        .ok_or(StakeChainErr::StakeSetupDataNotFound(
            cfg.operator_table.pov_op_key().clone(),
        ))?;
    let connector_p = ConnectorP::new(agg_key, stake_data.hash, cfg.network);

    let connector_cpfp = ConnectorCpfp::new(reimbursement_key, cfg.network);

    let payout_tx = PayoutTx::new(
        payout_data,
        &connector_a3,
        connector_n_of_n,
        connector_p,
        connector_cpfp,
    );
    let payout_txid = payout_tx.compute_txid();

    info!(%deposit_txid, %payout_txid, "finalizing payout transaction with aggregated signatures");
    let signed_payout_tx =
        payout_tx.finalize(connector_a3, agg_sigs.map(|agg_sig| agg_sig.signature));

    let payout_txid = signed_payout_tx.compute_txid();
    info!(%deposit_idx, %deposit_txid, %payout_txid, "submitting payout transaction to the tx-driver");
    output_handles
        .tx_driver
        .drive(signed_payout_tx, TxStatus::is_buried)
        .await?;

    Ok(())
}

fn create_assert_data_connectors(
    network: Network,
    wots_pks: WotsPublicKeys,
) -> (
    // NOTE: these constants are inferred from `wots_pks`
    ConnectorA256Factory<3, 5, 0, 0>,
    ConnectorAHashFactory<33, 10, 3, 11>,
) {
    let public_keys_256 = std::array::from_fn(|i| match i {
        0 => *wots_pks.groth16.public_inputs[0],
        i => *wots_pks.groth16.fqs[i - 1],
    });

    let connector_a256_factory = ConnectorA256Factory {
        network,
        public_keys: public_keys_256,
    };

    let connector_a_hash_factory = ConnectorAHashFactory {
        network,
        public_keys: wots_pks
            .groth16
            .hashes
            .into_iter()
            .map(|g16_hash| *g16_hash)
            .collect::<Vec<_>>()
            .try_into()
            .expect("must have the right size"),
    };

    (connector_a256_factory, connector_a_hash_factory)
}
