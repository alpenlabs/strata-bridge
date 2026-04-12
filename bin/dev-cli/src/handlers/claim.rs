use anyhow::bail;
use bitcoin::{
    key::TapTweak,
    sighash::{Prevouts, SighashCache},
    TapSighashType,
};
use bitcoincore_rpc::RpcApi;
use secp256k1::SECP256K1;
use strata_bridge_common::params::Params;
use strata_bridge_key_deriv::WalletKeys;
use strata_bridge_primitives::types::GraphIdx;
use strata_bridge_rpc::traits::{StrataBridgeControlApiClient, StrataBridgeDaApiClient};
use tracing::info;

use crate::{
    cli,
    handlers::{derive_keys, graph, rpc},
};

/// Post a claim transaction for the given graph idx.
///
/// Reconstructs the game graph from on-chain data, signs the claim transaction
/// with the derived stakechain wallet key and broadcasts it.
pub(crate) async fn handle_claim(args: cli::ClaimArgs) -> anyhow::Result<()> {
    let params = Params::from_path(&args.params)?;
    let operator_keys = derive_keys::derive_operator_keys(&args.seed, params.network)?;
    let wallet_keys = WalletKeys::derive(operator_keys.base_xpriv())
        .map_err(|e| anyhow::anyhow!("failed to derive wallet keys: {}", e))?;
    let stakechain_keypair = wallet_keys.stakechain;

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
        "posting claim"
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

    let (game_graph, _connectors) = graph::build_game_graph(&params, graph_data)?;
    info!(?graph_idx, "reconstructed game graph");

    let claim_tx = game_graph.claim;
    // The claim tx is constructed with exactly one input (the stakechain funding outpoint).
    let unsigned_claim_tx = claim_tx.as_ref().clone();
    let claim_txid = unsigned_claim_tx.compute_txid();

    // Fetch the claim funding prevout from Bitcoin to compute the sighash
    let claim_funding_outpoint = unsigned_claim_tx.input[0].previous_output;
    let funding_tx = btc_client
        .get_raw_transaction(&claim_funding_outpoint.txid, None)
        .map_err(|e| {
            anyhow::anyhow!(
                "failed to fetch claim funding transaction {}: {}",
                claim_funding_outpoint.txid,
                e
            )
        })?;
    let claim_prevout = funding_tx
        .output
        .get(claim_funding_outpoint.vout as usize)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "claim funding outpoint vout {} out of range for tx {}",
                claim_funding_outpoint.vout,
                claim_funding_outpoint.txid
            )
        })?
        .clone();

    let prevouts = Prevouts::All(&[claim_prevout]);
    let mut sighash_cache = SighashCache::new(&unsigned_claim_tx);
    let sighash = sighash_cache
        .taproot_key_spend_signature_hash(0, &prevouts, TapSighashType::Default)
        .map_err(|e| anyhow::anyhow!("failed to create claim input sighash: {}", e))?;

    let msg = secp256k1::Message::from_digest_slice(sighash.as_ref())
        .map_err(|e| anyhow::anyhow!("failed to create message from sighash: {}", e))?;

    // Assumes the claim funding output is a BIP86 key-path spend under the un-merkled stakechain
    // key.
    let signature = stakechain_keypair
        .tap_tweak(SECP256K1, None)
        .to_keypair()
        .sign_schnorr(msg);

    let mut signed_claim_tx = unsigned_claim_tx.clone();
    signed_claim_tx.input[0].witness.push(signature.serialize());

    let txid = btc_client
        .send_raw_transaction(&signed_claim_tx)
        .map_err(|e| anyhow::anyhow!("failed to broadcast claim transaction: {}", e))?;
    info!(?graph_idx, ?txid, %claim_txid, "broadcast claim transaction");

    Ok(())
}
