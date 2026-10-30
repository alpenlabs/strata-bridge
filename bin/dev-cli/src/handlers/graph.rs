use std::num::NonZero;

use bitcoin::relative;
use strata_bridge_common::params::Params;
use strata_bridge_rpc::types::RpcGraphData;
use strata_bridge_tx_graph::game_graph::{GameConnectors, GameData, GameGraph, ProtocolParams};
use strata_mosaic_client_api::types::COUNTERPROOF_N_DATA;

/// Reconstructs the game graph from protocol params and graph data fetched from the bridge node.
pub(crate) fn build_game_graph(
    params: &Params,
    graph_data: RpcGraphData,
) -> anyhow::Result<(GameGraph, GameConnectors)> {
    let protocol_params = ProtocolParams {
        network: params.network,
        magic_bytes: params.protocol.magic_bytes,
        contest_timelock: relative::Height::from(params.protocol.contest_timelock),
        proof_timelock: relative::Height::from(params.protocol.proof_timelock),
        ack_timelock: relative::Height::from(params.protocol.ack_timelock),
        nack_timelock: relative::Height::from(params.protocol.nack_timelock),
        contested_payout_timelock: relative::Height::from(
            params.protocol.contested_payout_timelock,
        ),
        counterproof_n_data: NonZero::new(COUNTERPROOF_N_DATA).expect("non-zero"),
        deposit_amount: params.protocol.deposit_amount,
        stake_amount: params.protocol.stake_amount,
    };

    let game_data = GameData {
        protocol: protocol_params,
        setup: graph_data.setup,
        deposit: graph_data.deposit,
    };

    Ok(GameGraph::new(game_data))
}
