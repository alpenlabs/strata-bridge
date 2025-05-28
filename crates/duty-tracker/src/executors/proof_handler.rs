//! Contains logic to handle proof generation.

use std::{fs, sync::Arc, time::Duration};

use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use bitcoin::{block::Header, Transaction, Txid};
use bitcoind_async_client::{traits::Reader, Client as BtcClient};
use secret_service_proto::v1::traits::*;
use strata_bridge_primitives::types::BitcoinBlockHeight;
use strata_bridge_proof_primitives::L1TxWithProofBundle;
use strata_bridge_proof_protocol::{
    BridgeProofInput, BridgeProofPublicOutput,
    REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX,
};
use strata_bridge_proof_snark::prover;
use strata_l1tx::{envelope::parser::parse_envelope_payloads, TxFilterConfig};
use strata_primitives::params::RollupParams;
use strata_state::batch::{Checkpoint, SignedCheckpoint};
use tracing::info;

use crate::{
    contract_manager::{ExecutionConfig, OutputHandles},
    contract_state_machine::TransitionErr,
    errors::ContractManagerErr,
    s2_session_manager::MusigSessionManager,
};

/// Prepares the data required to generate the bridge proof.
pub(super) async fn prepare_proof_input(
    cfg: &ExecutionConfig,
    deposit_idx: u32,
    output_handles: Arc<OutputHandles>,
    withdrawal_fulfillment_txid: Txid,
    start_height: BitcoinBlockHeight,
) -> Result<BridgeProofInput, ContractManagerErr> {
    info!(%withdrawal_fulfillment_txid, %start_height, "preparing header chain");
    let ProofHeaderChain {
        headers,
        withdrawal_fulfillment_tx,
        strata_checkpoint_tx,
    } = prepare_header_chain(
        cfg,
        &output_handles.bitcoind_rpc_client,
        withdrawal_fulfillment_txid,
        start_height,
    )
    .await?;

    let MusigSessionManager { s2_client, .. } = &output_handles.s2_session_manager;
    let op_signature = s2_client
        .musig2_signer()
        .sign_no_tweak(withdrawal_fulfillment_txid.as_ref())
        .await?
        .as_ref()
        .into();

    Ok(BridgeProofInput {
        pegout_graph_params: cfg.pegout_graph_params,
        rollup_params: cfg.sidesystem_params.clone(),
        headers,
        deposit_idx,
        withdrawal_fulfillment_tx,
        strata_checkpoint_tx,
        op_signature,
    })
}

struct ProofHeaderChain {
    headers: Vec<Header>,
    withdrawal_fulfillment_tx: (L1TxWithProofBundle, usize),
    strata_checkpoint_tx: (L1TxWithProofBundle, usize),
}

async fn prepare_header_chain(
    cfg: &ExecutionConfig,
    btc_client: &BtcClient,
    withdrawal_fulfillment_txid: Txid,
    start_height: BitcoinBlockHeight,
) -> Result<ProofHeaderChain, ContractManagerErr> {
    let start_height = start_height as u32;
    let mut height = start_height;

    let mut headers: Vec<Header> = vec![];
    let mut withdrawal_fulfillment_tx = None;
    let mut strata_checkpoint_tx = None;

    let mut num_blocks_after_fulfillment = 0;
    let poll_interval = Duration::from_secs(10); // FIXME: (@Rajil1213) replace with block time

    loop {
        let Ok(block) = btc_client.get_block_at(height as u64).await else {
            tokio::time::sleep(poll_interval).await;
            continue;
        };

        // Only set `checkpoint` if it's currently `None` and we find a matching tx
        strata_checkpoint_tx = strata_checkpoint_tx.or_else(|| {
            block
                .txdata
                .iter()
                .enumerate()
                .find(|(_, tx)| {
                    checkpoint_last_verified_l1_height(tx, &cfg.sidesystem_params).is_some()
                })
                .map(|(idx, tx)| {
                    let height = block.bip34_block_height().unwrap() as u32;
                    info!(
                        event = "found checkpoint",
                        %height,
                        checkpoint_txid = %tx.compute_txid()
                    );
                    (
                        L1TxWithProofBundle::generate(&block.txdata, idx as u32),
                        (height - start_height) as usize,
                    )
                })
        });

        // Only set `withdrawal_fulfillment` if it's currently `None` and we find a matching tx
        withdrawal_fulfillment_tx = withdrawal_fulfillment_tx.or_else(|| {
            block
                .txdata
                .iter()
                .enumerate()
                .find(|(_, tx)| tx.compute_txid() == withdrawal_fulfillment_txid)
                .map(|(idx, _)| {
                    let height = block.bip34_block_height().unwrap() as u32;
                    info!(
                        event = "found withdrawal fulfillment",
                        %height,
                        %withdrawal_fulfillment_txid
                    );
                    (
                        L1TxWithProofBundle::generate(&block.txdata, idx as u32),
                        (height - start_height) as usize,
                    )
                })
        });

        let header = block.header;
        headers.push(header);
        height += 1;

        if withdrawal_fulfillment_tx.is_some() {
            num_blocks_after_fulfillment += 1;
        }

        if num_blocks_after_fulfillment > REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX {
            info!(event = "blocks period complete", total_blocks = %headers.len());
            break;
        }
    }

    let Some(withdrawal_fulfillment_tx) = withdrawal_fulfillment_tx else {
        return Err(ContractManagerErr::FatalErr(
            "could not find withdrawal fulfillment tx".into(),
        ));
    };

    let Some(strata_checkpoint_tx) = strata_checkpoint_tx else {
        return Err(ContractManagerErr::FatalErr(
            "could not find checkpoint tx".into(),
        ));
    };

    fs::write("blocks.bin", bincode::serialize(&headers).unwrap())
        .expect("failed to write blocks to file");

    Ok(ProofHeaderChain {
        headers,
        withdrawal_fulfillment_tx,
        strata_checkpoint_tx,
    })
}

/// Generates the proof, the scalars and the public outputs for the given input.
pub(super) fn generate_proof(
    input: &BridgeProofInput,
) -> Result<(Proof<Bn254>, [Fr; 1], BridgeProofPublicOutput), ContractManagerErr> {
    prover::sp1_prove(input).map_err(|e| {
        ContractManagerErr::TransitionErr(TransitionErr(format!(
            "could not generate proof due to {e:?}"
        )))
    })
}

fn checkpoint_last_verified_l1_height(
    tx: &Transaction,
    rollup_params: &RollupParams,
) -> Option<u64> {
    let filter_config =
        TxFilterConfig::derive_from(rollup_params).expect("rollup params must be valid");

    if let Some(script) = tx.input[0].witness.taproot_leaf_script() {
        let script = script.script.to_bytes();
        if let Ok(inscription) = parse_envelope_payloads(&script.into(), &filter_config) {
            if inscription.is_empty() {
                return None;
            }
            if let Ok(signed_checkpoint) =
                borsh::from_slice::<SignedCheckpoint>(inscription[0].data())
            {
                let checkpoint: Checkpoint = signed_checkpoint.into();
                return Some(checkpoint.batch_info().epoch());
            }
        }
    }

    None
}
