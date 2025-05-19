use std::sync::Arc;

use bitcoin::{taproot, Network, ScriptBuf, Txid};
use bitvm::chunk::api::generate_assertions;
use futures::future::join_all;
use secret_service_proto::v1::traits::*;
use strata_bridge_connectors::prelude::{
    ConnectorA256Factory, ConnectorAHashFactory, ConnectorC0, ConnectorCpfp, ConnectorNOfN,
};
use strata_bridge_primitives::{constants::NUM_ASSERT_DATA_TX, wots::Assertions};
use strata_bridge_proof_snark::bridge_vk;
use strata_bridge_tx_graph::transactions::prelude::{
    AssertDataTxBatch, AssertDataTxInput, PreAssertData, PreAssertTx,
};
use strata_p2p_types::WotsPublicKeys;
use tracing::{error, info};

use crate::{
    contract_manager::{ExecutionConfig, OutputHandles},
    contract_state_machine::TransitionErr,
    errors::ContractManagerErr,
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
    info!("executing duty to publish pre-assert tx");

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
    let wots_pks = get_wots_pks(deposit_idx, deposit_txid, s2_client).await?;

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

    output_handles.tx_driver.drive(signed_pre_assert_tx).await?;

    Ok(())
}

pub(crate) async fn handle_publish_assert_data(
    cfg: &ExecutionConfig,
    output_handles: Arc<OutputHandles>,
    deposit_txid: Txid,
    pre_assert_txid: Txid,
    pre_assert_locking_scripts: [ScriptBuf; NUM_ASSERT_DATA_TX],
    withdrawal_fulfillment_txid: Txid,
    start_height: u64,
) -> Result<(), ContractManagerErr> {
    // prepare proof input
    let input = prepare_proof_input(
        cfg,
        output_handles.clone(),
        withdrawal_fulfillment_txid,
        start_height,
    )?;

    // generate the proof
    let (proof, scalars, public_params) = generate_proof(&input)?;

    // generate assertions
    let groth16_assertions = generate_assertions(
        proof,
        scalars.to_vec(),
        &bridge_vk::GROTH16_VERIFICATION_KEY,
    )
    .map_err(|e| TransitionErr(format!("could not generate assertions due to {e:?}")))?;

    let assertions = Assertions {
        withdrawal_fulfillment: public_params.withdrawal_fulfillment_txid.0,
        groth16: groth16_assertions,
    };

    // prepare assert-data txs
    let assert_data_batch_input = AssertDataTxInput {
        pre_assert_txid,
        pre_assert_locking_scripts,
    };

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
        AssertDataTxBatch::new(assert_data_batch_input, connector_n_of_n, connector_cpfp);

    // commit to assertions
    let MusigSessionManager { s2_client, .. } = &output_handles.s2_session_manager;
    let wots_client = s2_client.wots_signer();
    let wots_signatures = sign_assertions(&wots_client, assertions).await?;

    // finalize assert-data txs
    let wots_pks = get_wots_pks(input.deposit_idx, deposit_txid, s2_client).await?;

    let (connector_a256_factory, connector_a_hash_factory) =
        create_assert_data_connectors(cfg.network, wots_pks);

    let signed_assert_data_txs = assert_data_tx_batch.finalize(
        connector_a_hash_factory,
        connector_a256_factory,
        wots_signatures,
    );

    // submit assert-data txs to the tx-driver
    join_all(
        signed_assert_data_txs
            .into_iter()
            .enumerate()
            .map(|(i, signed_assert_data_tx)| {
                let txid = signed_assert_data_tx.compute_txid();
                info!(txid = %txid, index=%i, "submitting assert-data transaction to the tx-driver");

                output_handles.tx_driver.drive(signed_assert_data_tx)
            })
    )
    .await
    .iter()
    .enumerate()
    .for_each(|(index, result)| {
        if let Err(e) = result {
            error!(%e, %index, "could not submit assert-data transaction to the tx-driver");
        }
    });

    Ok(())
}

pub(crate) async fn handle_publish_post_assert(
    _cfg: &ExecutionConfig,
    _output_handles: Arc<OutputHandles>,
    _agg_sigs: [taproot::Signature; NUM_ASSERT_DATA_TX],
) -> Result<(), ContractManagerErr> {
    todo!()
}

fn create_assert_data_connectors(
    network: Network,
    wots_pks: WotsPublicKeys,
) -> (
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
