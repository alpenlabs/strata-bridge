use anyhow::bail;
use bitcoincore_rpc::RpcApi;
use secp256k1::{Keypair, SECP256K1};
use strata_bridge_common::params::Params;
use strata_bridge_key_deriv::Musig2Keys;
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_rpc::traits::{StrataBridgeControlApiClient, StrataBridgeDaApiClient};
use strata_bridge_tx_graph::transactions::bridge_proof::{BridgeProofData, BridgeProofTx};
use tracing::info;

use crate::{
    cli,
    handlers::{derive_keys, graph, rpc},
};

/// Post an empty (faulty) bridge proof receipt — `fn_counterproof` relies on
/// watchtowers refuting this.
pub(crate) async fn handle_bridge_proof(args: cli::BridgeProofArgs) -> anyhow::Result<()> {
    let params = Params::from_path(&args.params)?;
    info!(
        deposit_idx = args.deposit_idx,
        operator_idx = args.operator_idx,
        "posting empty bridge proof receipt"
    );
    post_bridge_proof(
        &params,
        &args.seed,
        &args.bridge_node_url,
        &args.btc_args,
        args.deposit_idx,
        args.operator_idx,
        vec![0u8; 128],
    )
    .await
}

/// DEMO ONLY: forge a REAL bridge proof for an arbitrary `(deposit, operator)`
/// claim and post it. The proof verifies despite the claim never being assigned,
/// because the bridge proof does not anchor the Moho genesis.
#[cfg(feature = "sp1")]
pub(crate) async fn handle_forge_bridge_proof(
    args: cli::ForgeBridgeProofArgs,
) -> anyhow::Result<()> {
    let params = Params::from_path(&args.params)?;
    info!(
        deposit_idx = args.deposit_idx,
        operator_idx = args.operator_idx,
        last_block_height = args.last_block_height,
        "forging real bridge proof for an unassigned claim"
    );
    let proof_bytes = forge_proof_bytes(&args).await?;
    post_bridge_proof(
        &params,
        &args.seed,
        &args.bridge_node_url,
        &args.btc_args,
        args.deposit_idx,
        args.operator_idx,
        proof_bytes,
    )
    .await
}

#[cfg(not(feature = "sp1"))]
pub(crate) async fn handle_forge_bridge_proof(
    _args: cli::ForgeBridgeProofArgs,
) -> anyhow::Result<()> {
    bail!("dev-cli was built without the `sp1` feature; rebuild with --features sp1 to forge bridge proofs")
}

/// Fetch ASM inputs for the chosen claim, prove the honest bridge ELF, and return
/// the borsh-encoded receipt bytes to embed in the bridge-proof transaction.
#[cfg(feature = "sp1")]
async fn forge_proof_bytes(args: &cli::ForgeBridgeProofArgs) -> anyhow::Result<Vec<u8>> {
    use ssz::Decode;
    use strata_asm_proto_bridge_v1::OperatorClaimUnlock;
    use strata_asm_proto_bridge_v1_txs::BRIDGE_V1_SUBPROTOCOL_ID;
    use strata_asm_rpc::traits::AsmProofApiClient;
    use strata_bridge_proof::{
        build_host, BridgeProofHost, BridgeProofInput, BridgeProofProgram, MerkleProofB32,
        MohoRecursiveOutput, MohoState, ProofBackendConfig, RecursiveMohoProof,
    };
    use strata_bridge_proof_common::prove;
    use strata_codec::encode_to_vec;
    use strata_crypto::hash;

    // Anchor the proof at the chosen L1 height.
    let btc = rpc::get_btc_client(
        &args.btc_args.url,
        args.btc_args.user.clone(),
        args.btc_args.pass.clone(),
    )?;
    let recent_block_hash = btc.get_block_hash(args.last_block_height)?;

    // jsonrpsee HttpClient implements `AsmProofApiClient`.
    let asm = rpc::get_bridge_client(&args.asm_rpc_url)?;

    // The bridge MMR leaf is hash(encode(OperatorClaimUnlock)).
    let claim = OperatorClaimUnlock::new(args.deposit_idx, args.operator_idx);
    let claim_unlock = encode_to_vec(&claim)?;
    let leaf_hash = hash::raw(&claim_unlock).0;

    let moho_state_bytes = asm
        .get_moho_state(recent_block_hash)
        .await?
        .ok_or_else(|| anyhow::anyhow!("moho state unavailable at anchor (height not proven?)"))?;
    let raw_moho_proof = asm
        .get_moho_proof(recent_block_hash)
        .await?
        .ok_or_else(|| anyhow::anyhow!("moho proof unavailable at anchor (height not proven?)"))?;
    let mmr_proof_bytes = asm
        .get_export_entry_mmr_proof(recent_block_hash, BRIDGE_V1_SUBPROTOCOL_ID, leaf_hash.to_vec())
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("mmr inclusion proof unavailable — is the forged claim seeded in genesis?")
        })?;

    let moho_state = MohoState::from_ssz_bytes(&moho_state_bytes)
        .map_err(|e| anyhow::anyhow!("decode moho_state ssz: {e:?}"))?;
    let mmr_proof = MerkleProofB32::from_ssz_bytes(&mmr_proof_bytes)
        .map_err(|e| anyhow::anyhow!("decode mmr_proof ssz: {e:?}"))?;
    let receipt = raw_moho_proof.0.receipt();
    let moho_output = MohoRecursiveOutput::from_ssz_bytes(receipt.public_values().as_bytes())
        .map_err(|e| anyhow::anyhow!("decode moho recursive output ssz: {e:?}"))?;
    let moho_proof = RecursiveMohoProof::new(
        moho_output.attestation().clone(),
        receipt.proof().as_bytes().to_vec(),
    );

    let input = BridgeProofInput {
        moho_state,
        moho_proof,
        claim_unlock,
        claim_unlock_inclusion_proof: mmr_proof,
    };

    // Honest, unmodified bridge ELF — the proof still verifies (the bug).
    let host = build_host(&ProofBackendConfig::Sp1 {
        elf_path: args.elf_path.clone(),
    })
    .await?;
    let proof_receipt = match host {
        BridgeProofHost::Sp1(h) => prove::<BridgeProofProgram, _>(input, *h).await?,
        BridgeProofHost::Native(h) => prove::<BridgeProofProgram, _>(input, h).await?,
    };

    Ok(borsh::to_vec(&proof_receipt)?)
}

/// Build clients, reconstruct the game graph, then sign + broadcast a bridge-proof
/// transaction carrying `proof_bytes`.
async fn post_bridge_proof(
    params: &Params,
    seed: &str,
    bridge_node_url: &str,
    btc_args: &cli::BtcArgs,
    deposit_idx: u32,
    operator_idx: u32,
    proof_bytes: Vec<u8>,
) -> anyhow::Result<()> {
    let operator_keys = derive_keys::derive_operator_keys(seed, params.network)?;
    let musig2_keys = Musig2Keys::derive(operator_keys.base_xpriv())
        .map_err(|e| anyhow::anyhow!("failed to derive musig2 keys: {}", e))?;
    let operator_keypair: Keypair = *musig2_keys.keypair;

    let btc_client =
        rpc::get_btc_client(&btc_args.url, btc_args.user.clone(), btc_args.pass.clone())?;
    let bridge_rpc_client = rpc::get_bridge_client(bridge_node_url)?;

    if let Err(e) = btc_client.get_blockchain_info() {
        bail!("unable to reach bitcoin node at {}: {}", btc_args.url, e);
    }
    if let Err(e) = bridge_rpc_client.get_uptime().await {
        bail!("unable to reach bridge node at {}: {}", bridge_node_url, e);
    }

    let graph_idx = GraphIdx {
        deposit: deposit_idx,
        operator: operator_idx,
    };

    let graph_data = bridge_rpc_client
        .get_graph_data(graph_idx)
        .await
        .map_err(|e| anyhow::anyhow!("failed to fetch graph data: {}", e))?;
    let graph_data = match graph_data {
        Some(data) => data,
        None => bail!("no graph data found for graph {:?}", graph_idx),
    };
    info!(?graph_idx, "fetched graph data");

    let game_index = graph_data.deposit.game_index;
    let (game_graph, connectors) = graph::build_game_graph(params, graph_data)?;
    info!(?graph_idx, "reconstructed game graph");

    let contest_txid = game_graph.contest.as_ref().compute_txid();

    let data = BridgeProofData {
        contest_txid,
        proof_bytes,
        game_index,
    };
    let bridge_proof_tx = BridgeProofTx::new(data, connectors.contest_proof);

    let tweaked_operator_keypair = operator_keypair
        .add_xonly_tweak(SECP256K1, &bridge_proof_tx.operator_key_tweak())
        .map_err(|e| anyhow::anyhow!("failed to tweak operator keypair: {}", e))?;

    let operator_signature = bridge_proof_tx
        .signing_info_partial()
        .sign(&tweaked_operator_keypair);
    let signed_tx = bridge_proof_tx.finalize_partial(operator_signature);

    let txid = btc_client
        .send_raw_transaction(&signed_tx)
        .map_err(|e| anyhow::anyhow!("failed to broadcast bridge proof transaction: {}", e))?;
    info!(?graph_idx, ?txid, "broadcast bridge proof transaction");

    Ok(())
}
