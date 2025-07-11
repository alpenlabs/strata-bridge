//! Contains logic to handle proof generation.

use std::{fs, time::Duration};

use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use bitcoin::{block::Header, Block, Txid};
use bitcoind_async_client::{traits::Reader, Client as BtcClient};
use secret_service_proto::v2::traits::*;
use strata_bridge_primitives::types::BitcoinBlockHeight;
use strata_bridge_proof_primitives::L1TxWithProofBundle;
use strata_bridge_proof_protocol::{
    BridgeProofInput, BridgeProofPublicOutput,
    REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX,
};
use strata_bridge_proof_snark::prover;
use strata_primitives::buf::Buf64;
use tracing::info;

use crate::{
    contract_manager::{ExecutionConfig, OutputHandles},
    contract_state_machine::TransitionErr,
    errors::ContractManagerErr,
    predicates::parse_strata_checkpoint,
};

/// Set this environment variable to 1 to dump test data required for prover unit tests.
const ENV_DUMP_TEST_DATA: &str = "DUMP_TEST_DATA";

/// File to dump the operator signature to, for testing purposes.
const OP_SIGNATURE_FILE: &str = "op_signature.bin";

/// File to dump the chainstate to, for testing purposes.
const CHAINSTATE_FILE: &str = "chainstate.borsh";

/// File to dump the blocks to, for testing purposes.
const BLOCKS_FILE: &str = "blocks.bin";

/// Checks if the test data should be dumped based on the environment variable
/// [`ENV_DUMP_TEST_DATA`].
fn should_dump_test_data() -> bool {
    std::env::var(ENV_DUMP_TEST_DATA).is_ok_and(|val| val == "1")
}

/// Prepares the data required to generate the bridge proof.
pub(super) async fn prepare_proof_input(
    cfg: &ExecutionConfig,
    deposit_idx: u32,
    output_handles: &OutputHandles,
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

    let s2_client = &output_handles.s2_client;

    let op_signature: Buf64 = s2_client
        .musig2_signer()
        .sign_no_tweak(withdrawal_fulfillment_txid.as_ref())
        .await?
        .as_ref()
        .into();

    if should_dump_test_data() {
        info!("dumping operator signature to file");
        if let Err(e) = fs::write(OP_SIGNATURE_FILE, op_signature.as_bytes()) {
            info!(%e, "failed to dump operator signature to file");
        } else {
            info!("dumped operator signature to file");
        }
    }

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

    let mut blocks: Vec<Block> = vec![];
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
            block.txdata.iter().enumerate().find_map(|(idx, tx)| {
                let checkpoint = parse_strata_checkpoint(tx, &cfg.sidesystem_params)?;

                let height = block.bip34_block_height().unwrap() as u32;
                info!(
                    event = "found checkpoint",
                    %height,
                    checkpoint_txid = %tx.compute_txid()
                );

                if should_dump_test_data() {
                    if let Err(e) = fs::write(CHAINSTATE_FILE, checkpoint.sidecar().chainstate()) {
                        info!(%e, "failed to dump chainstate to file");
                    } else {
                        info!("dumped chainstate to file");
                    }
                }

                Some((
                    L1TxWithProofBundle::generate(&block.txdata, idx as u32),
                    (height - start_height) as usize,
                ))
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

        blocks.push(block);
        height += 1;

        if withdrawal_fulfillment_tx.is_some() {
            num_blocks_after_fulfillment += 1;
        }

        info!(%height, %num_blocks_after_fulfillment, "parsed block");

        if num_blocks_after_fulfillment > REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX {
            info!(event = "blocks period complete", total_blocks = %blocks.len());
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

    if should_dump_test_data() {
        info!("dumping blocks to file");

        if let Err(e) = fs::write(BLOCKS_FILE, bincode::serialize(&blocks).unwrap()) {
            info!(%e, "failed to dump blocks to file");
        } else {
            info!("dumped blocks to file");
        }
    }

    Ok(ProofHeaderChain {
        headers: blocks.into_iter().map(|b| b.header).collect(),
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
