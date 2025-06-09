use std::ops::Deref;

use anyhow::{anyhow, bail};
use bitcoin::{Transaction, TxOut};
use bitcoincore_rpc::{json::AddressType, RpcApi};
use bitvm::chunk::api::{api_generate_full_tapscripts, validate_assertions};
use musig2::KeyAggContext;
use secp256k1::Parity;
use sp1_verifier::{blake3_hash, hash_public_inputs_with_fn};
use strata_bridge_connectors::{
    partial_verification_scripts::PARTIAL_VERIFIER_SCRIPTS,
    prelude::{
        ConnectorA3, ConnectorA3Leaf, ConnectorStake, DisprovePublicInputsCommitmentWitness,
        StakeSpendPath,
    },
};
use strata_bridge_primitives::{
    constants::NUM_ASSERT_DATA_TX,
    scripts::prelude::wots_to_byte_array,
    wots::{self, Groth16Sigs, Wots256Sig},
};
use strata_bridge_proof_protocol::BridgeProofPublicOutput;
use strata_bridge_proof_snark::bridge_vk;
use strata_bridge_rpc::{traits::StrataBridgeDaApiClient, types::RpcDisproveData};
use strata_bridge_tx_graph::transactions::{
    claim::ClaimTx,
    prelude::{AssertDataTxBatch, DisproveData, DisproveTx},
};
use tracing::{info, warn};

use super::rpc;
use crate::{cli, params::Params};

pub(crate) async fn handle_disprove(args: cli::DisproveArgs) -> anyhow::Result<()> {
    let params: Params = Params::from_path(&args.params)?;

    let btc_client =
        rpc::get_btc_client(&args.btc_args.url, args.btc_args.user, args.btc_args.pass)?;
    let bridge_client = rpc::get_bridge_client(&args.bridge_node_url)?;

    info!(post_assert_txid=%args.post_assert_txid, "fetching post-assert transaction");
    let post_assert_tx = btc_client
        .get_raw_transaction(&args.post_assert_txid, None)
        .map_err(|e| anyhow!(format!("could not fetch post-assert transaction: {e}")))?;

    info!("fetching assert-data transactions");

    let assert_data_txs: [Transaction; NUM_ASSERT_DATA_TX] = post_assert_tx
        .input
        .iter()
        .enumerate()
        .map(|(index, input)| {
            info!(%index, "fetching assert-data tx");
            btc_client
                .get_raw_transaction(&input.previous_output.txid, None)
                .map_err(|e| anyhow!(format!("could not fetch assert-data tx {index}: {e}")))
        })
        .collect::<Result<Vec<Transaction>, _>>()?
        .try_into()
        .map_err(|_| {
            anyhow!(format!(
                "post-assert tx must have exactly {NUM_ASSERT_DATA_TX} inputs"
            ))
        })?;

    let pre_assert_txid = assert_data_txs[0].input[0].previous_output.txid;
    info!(%pre_assert_txid, "fetching pre-assert tx");
    let pre_assert_tx = btc_client
        .get_raw_transaction(&pre_assert_txid, None)
        .map_err(|e| anyhow!(format!("could not fetch pre-assert transaction: {e}")))?;

    let claim_txid = pre_assert_tx.input[0].previous_output.txid;
    info!(%claim_txid, "fetching claim transaction");
    let claim_tx = btc_client
        .get_raw_transaction(&claim_txid, None)
        .map_err(|e| anyhow!(format!("could not fetch claim transaction: {e}")))?;

    let Some(disprove_data) = bridge_client.get_disprove_data(claim_txid).await? else {
        bail!(format!(
            "disprove data does not exist for claim ({claim_txid})"
        ))
    };

    info!("parsing claim transaction witness");
    let withdrawal_fulfillment_txid =
        ClaimTx::parse_witness(&claim_tx).expect("claim tx must have valid witness");

    info!("parsing assert-data transactions witnesses");
    let groth16 = AssertDataTxBatch::parse_witnesses(&assert_data_txs)
        .expect("assert-data txs must have valid witnesses");

    let signatures = wots::Signatures {
        withdrawal_fulfillment: Wots256Sig(withdrawal_fulfillment_txid),
        groth16: Groth16Sigs(groth16.clone()),
    };

    let RpcDisproveData {
        post_assert_txid,
        deposit_txid,
        stake_outpoint,
        operator_pubkey,
        stake_hash,
        wots_public_keys,
        n_of_n_sig,
    } = disprove_data;

    let Some(disprove_leaf) = get_disprove_leaf(signatures, deposit_txid, &wots_public_keys) else {
        info!("no disprove leaf found, nothing to do");
        return Ok(());
    };

    info!("construcing disprove transaction");

    let disprove_input = DisproveData {
        post_assert_txid,
        deposit_txid,
        stake_outpoint,
        network: params.network,
    };

    let agg_pubkey = KeyAggContext::new(
        params
            .musig2_keys
            .into_iter()
            .map(|k| k.public_key(Parity::Even)),
    )
    .expect("must be able to aggregate keys")
    .aggregated_pubkey();

    let connector_a3 = ConnectorA3::new(
        params.network,
        deposit_txid,
        agg_pubkey,
        wots_public_keys.clone(),
        params.payout_timelock,
    );

    let connector_stake = ConnectorStake::new(
        agg_pubkey,
        operator_pubkey,
        stake_hash,
        params.stake_chain_delta,
        params.network,
    );

    let disprove_tx = DisproveTx::new(
        disprove_input,
        params.stake_amount,
        params.burn_amount,
        &connector_a3,
        connector_stake,
    );

    let address = btc_client
        .get_new_address(None, Some(AddressType::Bech32m))?
        .require_network(params.network)?;
    let reward = TxOut {
        value: params.stake_amount - params.burn_amount, // FIXME: (@Rajil1213) add fees
        script_pubkey: address.script_pubkey(),
    };

    info!(?reward, "finalizing disprove transaction");

    let disprove_path = StakeSpendPath::Disprove(n_of_n_sig);
    let signed_disprove_tx =
        disprove_tx.finalize(reward, disprove_path, disprove_leaf, connector_a3);
    let disprove_txid = signed_disprove_tx.compute_txid();
    let disprove_tx_size = signed_disprove_tx.vsize();

    info!(%disprove_txid, %disprove_tx_size, "broadcasting disprove transaction");
    let disprove_txid = btc_client
        .send_raw_transaction(&signed_disprove_tx)
        .map_err(|e| anyhow!(format!("could not broadcast disprove transaction: {e}")))?;

    info!(%disprove_txid, "disprove transaction broadcasted successfully");

    Ok(())
}

fn get_disprove_leaf(
    signatures: wots::Signatures,
    deposit_txid: bitcoin::Txid,
    wots_public_keys: &wots::PublicKeys,
) -> Option<ConnectorA3Leaf> {
    info!(action = "verifying public input hash");

    let wots::Signatures {
        withdrawal_fulfillment: withdrawal_fulfillment_txid,
        groth16,
    } = signatures;

    let withdrawal_txid: [u8; 32] = wots_to_byte_array(*withdrawal_fulfillment_txid).into();
    let public_inputs = BridgeProofPublicOutput {
        deposit_txid: deposit_txid.into(),
        withdrawal_fulfillment_txid: withdrawal_txid.into(),
    };

    // NOTE: This is zkvm-specific logic
    let serialized_public_inputs = borsh::to_vec(&public_inputs).unwrap();
    let public_inputs_hash = hash_public_inputs_with_fn(&serialized_public_inputs, blake3_hash);

    let committed_public_inputs_hash = wots_to_byte_array((*groth16).0[0]);

    // flip nibbles to comply with the expected format
    let committed_public_inputs_hash =
        committed_public_inputs_hash.map(|b| ((b & 0xf0) >> 4) | ((b & 0x0f) << 4));

    if public_inputs_hash != committed_public_inputs_hash {
        warn!(
            expected = ?public_inputs_hash,
            committed = ?committed_public_inputs_hash,
            msg = "public inputs hash mismatch"
        );

        return Some(ConnectorA3Leaf::DisprovePublicInputsCommitment {
            deposit_txid,
            witness: Some(DisprovePublicInputsCommitmentWitness {
                sig_withdrawal_fulfillment_txid: *withdrawal_fulfillment_txid,
                sig_public_inputs_hash: (*groth16).0[0],
            }),
        });
    }

    info!("generating complete disprove scripts");
    let complete_disprove_scripts =
        api_generate_full_tapscripts(*wots_public_keys.groth16, &PARTIAL_VERIFIER_SCRIPTS);

    info!("validating assertions");
    if let Some((tapleaf_index, witness_script)) = validate_assertions(
        &bridge_vk::GROTH16_VERIFICATION_KEY,
        groth16.deref().clone(),
        *wots_public_keys.groth16,
        &complete_disprove_scripts,
    ) {
        warn!(disprove_leaf=%tapleaf_index, "groth16 assertion invalid");
        let disprove_script = complete_disprove_scripts[tapleaf_index].clone();
        Some(ConnectorA3Leaf::DisproveProof {
            disprove_script,
            witness_script: Some(witness_script),
        })
    } else {
        info!("groth16 assertions are valid");
        None
    }
}
