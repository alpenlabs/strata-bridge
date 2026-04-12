use anyhow::bail;
use bitcoincore_rpc::RpcApi;
use strata_bridge_common::params::Params;
use strata_bridge_key_deriv::Musig2Keys;
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_rpc::traits::{StrataBridgeControlApiClient, StrataBridgeDaApiClient};
use strata_bridge_tx_graph::musig_functor::GameFunctor;
use tracing::info;

use crate::{
    cli,
    handlers::{derive_keys, graph, rpc},
};

/// Publish a contest transaction for the given graph idx.
///
/// Reconstructs the game graph from on-chain data and pre-signed aggregate signatures,
/// then signs the contest transaction with the derived watchtower key and broadcasts it.
pub(crate) async fn handle_contest(args: cli::ContestArgs) -> anyhow::Result<()> {
    let params = Params::from_path(&args.params)?;
    let operator_keys = derive_keys::derive_operator_keys(&args.seed, params.network)?;
    let musig2_keys = Musig2Keys::derive(operator_keys.base_xpriv())
        .map_err(|e| anyhow::anyhow!("failed to derive musig2 keys: {}", e))?;
    let watchtower_keypair = musig2_keys.keypair;

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
        "contesting claim"
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

    let agg_sigs = bridge_rpc_client
        .get_aggregate_signatures(graph_idx)
        .await
        .map_err(|e| anyhow::anyhow!("failed to fetch aggregate signatures: {}", e))?;
    let agg_sigs = match agg_sigs {
        Some(sigs) => sigs,
        None => bail!("no aggregate signatures found for graph {:?}", graph_idx),
    };
    info!(?graph_idx, "fetched aggregate signatures");

    let (game_graph, _connectors) = graph::build_game_graph(&params, graph_data)?;
    info!(?graph_idx, "reconstructed game graph");

    // Watchtower index: contester's position excluding the graph owner
    let graph_owner_idx = args.operator_idx;
    let contester = args.contester_node_idx;
    let watchtower_index = if contester < graph_owner_idx {
        contester
    } else {
        contester - 1
    };

    let contest = game_graph.contest;
    let presigned = GameFunctor::unpack(agg_sigs.signatures, contest.n_watchtowers() as usize)
        .ok_or_else(|| anyhow::anyhow!("invalid aggregate signature count for game graph"))?;
    let n_of_n_signature = presigned
        .watchtowers
        .get(watchtower_index as usize)
        .map(|wt| wt.contest[0])
        .ok_or_else(|| {
            anyhow::anyhow!(
                "missing contest signature for watchtower index {}",
                watchtower_index
            )
        })?;
    info!(
        ?n_of_n_signature,
        watchtower_index, "retrieved contest n-of-n signature"
    );

    let signing_info = contest.signing_info(watchtower_index);
    let watchtower_signature = signing_info.sign(&watchtower_keypair);
    let contest_tx = contest.finalize(n_of_n_signature, watchtower_index, watchtower_signature);

    let txid = btc_client
        .send_raw_transaction(&contest_tx)
        .map_err(|e| anyhow::anyhow!("failed to broadcast contest transaction: {}", e))?;
    info!(?graph_idx, ?txid, "broadcast contest transaction");

    Ok(())
}
