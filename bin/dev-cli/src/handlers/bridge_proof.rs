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

/// Post an empty bridge proof receipt transaction for the given graph idx.
pub(crate) async fn handle_bridge_proof(args: cli::BridgeProofArgs) -> anyhow::Result<()> {
    let params = Params::from_path(&args.params)?;
    let operator_keys = derive_keys::derive_operator_keys(&args.seed, params.network)?;
    let musig2_keys = Musig2Keys::derive(operator_keys.base_xpriv())
        .map_err(|e| anyhow::anyhow!("failed to derive musig2 keys: {}", e))?;
    let operator_keypair: Keypair = *musig2_keys.keypair;

    let btc_client =
        rpc::get_btc_client(&args.btc_args.url, args.btc_args.user, args.btc_args.pass)?;
    let bridge_rpc_client = rpc::get_bridge_client(&args.bridge_node_url)?;

    if let Err(e) = btc_client.get_blockchain_info() {
        bail!(
            "unable to reach bitcoin node at {}: {}",
            args.btc_args.url,
            e
        );
    }

    if let Err(e) = bridge_rpc_client.get_uptime().await {
        bail!(
            "unable to reach bridge node at {}: {}",
            args.bridge_node_url,
            e
        );
    }

    let graph_idx = GraphIdx {
        deposit: args.deposit_idx,
        operator: args.operator_idx,
    };
    info!(
        deposit_idx = args.deposit_idx,
        operator_idx = args.operator_idx,
        "posting empty bridge proof receipt"
    );

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

    let (game_graph, connectors) = graph::build_game_graph(&params, graph_data)?;
    info!(?graph_idx, "reconstructed game graph");

    let contest_txid = game_graph.contest.as_ref().compute_txid();

    let data = BridgeProofData {
        contest_txid,
        proof_bytes: vec![0u8; 128],
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
