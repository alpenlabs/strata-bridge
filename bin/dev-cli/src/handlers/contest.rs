use std::{num::NonZero, str::FromStr};

use anyhow::bail;
use bitcoin::{bip32::Xpriv, relative, Network};
use bitcoincore_rpc::RpcApi;
use strata_bridge_key_deriv::{Musig2Keypair, Musig2Keys, OperatorKeys};
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_rpc::traits::{StrataBridgeControlApiClient, StrataBridgeDaApiClient};
use strata_bridge_tx_graph::{
    game_graph::{GameData, GameGraph, ProtocolParams},
    musig_functor::GameFunctor,
};
use strata_l1_txfmt::MagicBytes;
use tracing::info;

use crate::{cli, handlers::rpc, params::Params};

/// Publish a contest transaction for the given graph idx.
///
/// Reconstructs the game graph from on-chain data and pre-signed aggregate signatures,
/// then signs the contest transaction with the derived watchtower key and broadcasts it.
pub(crate) async fn handle_contest(args: cli::ContestArgs) -> anyhow::Result<()> {
    let params = Params::from_path(&args.params)?;
    let watchtower_keypair = derive_musig2_keypair(&args.seed, params.network)?;

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

    let protocol_params = ProtocolParams {
        network: params.network,
        magic_bytes: MagicBytes::from_str(&params.tag)?,
        contest_timelock: relative::Height::from(params.contest_timelock),
        proof_timelock: relative::Height::from(params.proof_timelock),
        ack_timelock: relative::Height::from(params.ack_timelock),
        nack_timelock: relative::Height::from(params.nack_timelock),
        contested_payout_timelock: relative::Height::from(params.contested_payout_timelock),
        // TODO: <https://atlassian.alpenlabs.net/browse/STR-2945>
        // use the COUNTERPROOF_N_BYTES constant in a future refactor
        // proof bytes (groth16) + deposit_idx (4 bytes) + operator pubkey (32 bytes)
        counterproof_n_bytes: NonZero::new(128 + 32 + 4).expect("non-zero"),
        deposit_amount: params.deposit_amount,
        stake_amount: params.stake_amount,
    };

    let game_data = GameData {
        protocol: protocol_params,
        setup: graph_data.setup,
        deposit: graph_data.deposit,
    };
    let (game_graph, _connectors) = GameGraph::new(game_data);
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

fn derive_musig2_keypair(seed_hex: &str, network: Network) -> anyhow::Result<Musig2Keypair> {
    let seed_bytes =
        hex::decode(seed_hex).map_err(|e| anyhow::anyhow!("invalid hex for seed: {}", e))?;
    let xpriv = Xpriv::new_master(network, &seed_bytes)
        .map_err(|e| anyhow::anyhow!("failed to derive master key from seed: {}", e))?;
    let operator_keys = OperatorKeys::new(&xpriv)
        .map_err(|e| anyhow::anyhow!("failed to derive operator keys: {}", e))?;
    let musig2_keys = Musig2Keys::derive(operator_keys.base_xpriv())
        .map_err(|e| anyhow::anyhow!("failed to derive musig2 keys: {}", e))?;
    Ok(musig2_keys.keypair)
}
