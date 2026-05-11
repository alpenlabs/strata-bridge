use anyhow::bail;
use bitcoin::hashes::{sha256, Hash};
use bitcoincore_rpc::RpcApi;
use strata_bridge_common::params::Params;
use strata_bridge_connectors::prelude::UnstakingIntentWitness;
use strata_bridge_key_deriv::PreimageIkm;
use strata_bridge_rpc::traits::{StrataBridgeControlApiClient, StrataBridgeDaApiClient};
use strata_bridge_tx_graph::{
    musig_functor::StakeFunctor,
    stake_graph::{StakeData, StakeGraph},
};
use tracing::info;

use crate::{
    cli,
    handlers::{derive_keys, rpc},
};

const STAKE_TX_INDEX: u32 = 0;

/// Post an unstaking intent transaction for the given operator stake graph.
pub(crate) async fn handle_unstaking_intent(args: cli::UnstakingIntentArgs) -> anyhow::Result<()> {
    let params = Params::from_path(&args.params)?;
    let operator_keys = derive_keys::derive_operator_keys(&args.seed, params.network)?;
    let preimage_ikm = PreimageIkm::derive(operator_keys.base_xpriv())
        .map_err(|e| anyhow::anyhow!("failed to derive stakechain preimage ikm: {}", e))?;

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

    info!(operator_idx = args.operator_idx, "posting unstaking intent");

    let stake_data = bridge_rpc_client
        .get_stake_data(args.operator_idx)
        .await
        .map_err(|e| anyhow::anyhow!("failed to fetch stake data: {}", e))?;
    let stake_data = match stake_data {
        Some(data) => data,
        None => bail!("no stake data found for operator {}", args.operator_idx),
    };
    if stake_data.context.operator_idx() != args.operator_idx {
        bail!(
            "stake data operator mismatch: requested {}, got {}",
            args.operator_idx,
            stake_data.context.operator_idx()
        );
    }
    info!(operator_idx = args.operator_idx, "fetched stake data");

    let agg_sigs = bridge_rpc_client
        .get_stake_aggregate_signatures(args.operator_idx)
        .await
        .map_err(|e| anyhow::anyhow!("failed to fetch stake aggregate signatures: {}", e))?;
    let agg_sigs = match agg_sigs {
        Some(sigs) => sigs,
        None => bail!(
            "no aggregate stake signatures found for operator {}",
            args.operator_idx
        ),
    };
    if agg_sigs.operator_idx != args.operator_idx {
        bail!(
            "stake aggregate signature operator mismatch: requested {}, got {}",
            args.operator_idx,
            agg_sigs.operator_idx
        );
    }
    info!(
        operator_idx = args.operator_idx,
        "fetched stake aggregate signatures"
    );

    let stake_funds = stake_data.setup.stake_funds;
    let preimage = preimage_ikm.derive_preimage(stake_funds.txid, stake_funds.vout, STAKE_TX_INDEX);
    let preimage_hash = sha256::Hash::hash(&preimage);
    if preimage_hash != stake_data.setup.unstaking_image {
        bail!(
            "derived preimage hash {} does not match stake data unstaking image {}",
            preimage_hash,
            stake_data.setup.unstaking_image
        );
    }
    info!(%stake_funds, %preimage_hash, "derived matching unstaking preimage");

    let stake_graph = StakeGraph::new(StakeData {
        protocol: stake_data.protocol,
        setup: stake_data.setup,
    });
    let presigned = StakeFunctor::unpack(agg_sigs.signatures)
        .ok_or_else(|| anyhow::anyhow!("invalid aggregate signature count for stake graph"))?;
    let witness = UnstakingIntentWitness {
        n_of_n_signature: presigned.unstaking_intent[0],
        unstaking_preimage: preimage,
    };
    let unstaking_intent_tx = stake_graph.unstaking_intent.finalize(&witness);
    let expected_txid = unstaking_intent_tx.compute_txid();

    let txid = btc_client
        .send_raw_transaction(&unstaking_intent_tx)
        .map_err(|e| anyhow::anyhow!("failed to broadcast unstaking intent transaction: {}", e))?;
    info!(
        operator_idx = args.operator_idx,
        %txid,
        %expected_txid,
        "broadcast unstaking intent transaction"
    );

    Ok(())
}
