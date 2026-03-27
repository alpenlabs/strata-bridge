use anyhow::bail;
use bitcoin::Transaction;
use bitcoincore_rpc::RpcApi;
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_rpc::traits::StrataBridgeControlApiClient;
use tracing::info;

use crate::{cli, handlers::rpc};

pub(crate) async fn handle_contest(args: cli::ContestArgs) -> anyhow::Result<()> {
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

    let _graph_idx = GraphIdx {
        deposit: args.deposit_idx,
        operator: args.operator_idx,
    };
    info!(
        deposit_idx = args.deposit_idx,
        operator_idx = args.operator_idx,
        "contesting claim"
    );

    // TODO: get graph data from bridge node and build the contest transaction
    let _contest_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    Ok(())
}
