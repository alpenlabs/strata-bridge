use std::sync::Arc;

use bitcoin::{taproot, Txid};
use secret_service_proto::v1::traits::*;
use strata_bridge_connectors::prelude::{
    ConnectorA256Factory, ConnectorAHashFactory, ConnectorC0, ConnectorCpfp,
};
use strata_bridge_tx_graph::transactions::prelude::{PreAssertData, PreAssertTx};
use tracing::info;

use crate::{
    contract_manager::{ExecutionConfig, OutputHandles},
    errors::ContractManagerErr,
    executors::wots_handler::get_wots_pks,
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

    let public_keys_256 = std::array::from_fn(|i| match i {
        0 => *wots_pks.groth16.public_inputs[i],
        i => *wots_pks.groth16.public_inputs[i - 1],
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
