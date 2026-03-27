use std::{num::NonZero, str::FromStr};

use anyhow::bail;
use bitcoin::{Address, relative};
use bitcoincore_rpc::RpcApi;
use secp256k1::{Keypair, SECP256K1};
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_rpc::traits::{StrataBridgeControlApiClient, StrataBridgeDaApiClient};
use strata_bridge_tx_graph::{
    game_graph::{GameData, GameGraph, ProtocolParams},
    musig_functor::GameFunctor,
};
use strata_l1_txfmt::MagicBytes;
use tracing::info;

use crate::{cli, handlers::rpc, params::Params};

pub(crate) async fn handle_contest(args: cli::ContestArgs) -> anyhow::Result<()> {
    let btc_client =
        rpc::get_btc_client(&args.btc_args.url, args.btc_args.user, args.btc_args.pass)?;
    let bridge_rpc_client = rpc::get_bridge_client(&args.bridge_node_url)?;
    let params = Params::from_path(&args.params)?;

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

    let protocol = ProtocolParams {
        network: params.network,
        magic_bytes: MagicBytes::from_str(&params.tag)?,
        contest_timelock: relative::Height::from(params.contest_timelock),
        proof_timelock: relative::Height::from(params.proof_timelock),
        ack_timelock: relative::Height::from(params.ack_timelock),
        nack_timelock: relative::Height::from(params.nack_timelock),
        contested_payout_timelock: relative::Height::from(params.contested_payout_timelock),
        // TODO: use the COUNTERPROOF_N_BYTES constant in a future refactor
        // proof bytes (groth16) + deposit_idx (4 bytes) + operator pubkey (32 bytes)
        counterproof_n_bytes: NonZero::new(128 + 32 + 4).expect("non-zero"),
        deposit_amount: params.deposit_amount,
        stake_amount: params.stake_amount,
    };

    let graph_ctx = graph_data.context.clone();
    let game_data = GameData {
        protocol,
        setup: graph_data.setup,
        deposit: graph_data.deposit,
    };
    let (game_graph, _connectors) = GameGraph::new(game_data);
    info!(?graph_idx, "reconstructed game graph");

    let graph_owner_idx = graph_ctx.operator_idx();
    let pov_idx = graph_ctx.operator_table().pov_idx();
    if pov_idx == graph_owner_idx {
        bail!(
            "cannot contest own graph: owner index {} equals local index {}",
            graph_owner_idx,
            pov_idx
        );
    }
    let watchtower_index = if pov_idx < graph_owner_idx {
        pov_idx
    } else {
        pov_idx - 1
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

    let watchtower_btc_key = graph_ctx
        .operator_table()
        .idx_to_btc_key(&pov_idx)
        .ok_or_else(|| anyhow::anyhow!("missing BTC key for local operator index {}", pov_idx))?;
    let watchtower_xonly = watchtower_btc_key.x_only_public_key().0;
    let watchtower_addr = Address::p2tr(SECP256K1, watchtower_xonly, None, params.network);
    let watchtower_privkey = btc_client
        .dump_private_key(&watchtower_addr)
        .map_err(|e| anyhow::anyhow!("failed to fetch private key for {}: {}", watchtower_addr, e))?;
    let watchtower_keypair = Keypair::from_secret_key(SECP256K1, &watchtower_privkey.inner);

    let signing_info = contest.signing_info(watchtower_index);
    let watchtower_signature = signing_info.sign(&watchtower_keypair);
    let contest_tx = contest.finalize(n_of_n_signature, watchtower_index, watchtower_signature);

    let txid = btc_client
        .send_raw_transaction(&contest_tx)
        .map_err(|e| anyhow::anyhow!("failed to broadcast contest transaction: {}", e))?;
    info!(?graph_idx, ?txid, "broadcast contest transaction");

    Ok(())
}
