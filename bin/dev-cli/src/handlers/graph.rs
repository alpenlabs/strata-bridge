use std::{num::NonZero, str::FromStr};

use bitcoin::relative;
use strata_bridge_rpc::types::RpcGraphData;
use strata_bridge_tx_graph::game_graph::{GameConnectors, GameData, GameGraph, ProtocolParams};
use strata_l1_txfmt::MagicBytes;

use crate::params::Params;

/// Reconstructs the game graph from protocol params and graph data fetched from the bridge node.
pub(crate) fn build_game_graph(
    params: &Params,
    graph_data: RpcGraphData,
) -> anyhow::Result<(GameGraph, GameConnectors)> {
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

    Ok(GameGraph::new(game_data))
}
