use anyhow::bail;
use bitcoin::{consensus, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, Witness};
use bitcoincore_rpc::{Client, RpcApi};
use strata_bridge_rpc::traits::StrataBridgeDaApiClient;
use tracing::info;

use crate::{cli, handlers::rpc};

pub(crate) async fn handle_challenge(args: cli::ChallengeArgs) -> anyhow::Result<()> {
    let btc_client =
        rpc::get_btc_client(&args.btc_args.url, args.btc_args.user, args.btc_args.pass)?;
    let bridge_rpc_client = rpc::get_bridge_client(&args.bridge_node_url)?;

    let claim_txid = args.claim_txid;
    info!(%claim_txid, "retrieving challenge transaction for claim");

    let Some(mut challenge_tx) = bridge_rpc_client
        .get_challenge_tx(args.claim_txid)
        .await
        .map_err(|e| {
            anyhow::anyhow!("Failed to get challenge signature from bridge node: {}", e)
        })?
    else {
        bail!(
            "challenge transaction not found for claim txid: {}",
            args.claim_txid
        );
    };

    info!(%claim_txid, "creating funding UTXO for challenge transaction");
    let funding_outpoint = create_funding_utxo(&btc_client, challenge_tx.output[0].value)
        .map_err(|e| anyhow::anyhow!("Failed to create funding UTXO: {}", e))?;

    challenge_tx.input.push(TxIn {
        previous_output: funding_outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    });

    let challenge_txid = challenge_tx.compute_txid();

    info!(%claim_txid, %challenge_txid, "signing challenge transaction");
    let raw_signed_challenge_tx = btc_client
        .sign_raw_transaction_with_wallet(&challenge_tx, None, None)
        .map_err(|e| anyhow::anyhow!("failed to sign challenge transaction: {}", e))?
        .hex;

    let signed_challenge_tx: Transaction = consensus::encode::deserialize(&raw_signed_challenge_tx)
        .map_err(|e| {
            anyhow::anyhow!("failed to deserialize signed challenge transaction: {}", e)
        })?;

    info!(%claim_txid, %challenge_txid, "broadcasting challenge transaction");
    let raw_signed_challenge_tx = consensus::encode::serialize(&signed_challenge_tx);
    btc_client
        .send_raw_transaction(&raw_signed_challenge_tx)
        .map_err(|e| anyhow::anyhow!("failed to send signed challenge transaction: {}", e))?;

    info!(%claim_txid, %challenge_txid, "challenge transaction broadcasted successfully");

    Ok(())
}

fn create_funding_utxo(client: &Client, amt: Amount) -> anyhow::Result<OutPoint> {
    let network = client
        .get_blockchain_info()
        .map_err(|e| anyhow::anyhow!("Failed to get blockchain info: {}", e))?
        .chain;

    let address = client
        .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))
        .map_err(|e| anyhow::anyhow!("Failed to get new address: {}", e))?
        .require_network(network)
        .expect("address must be valid for network");

    let txid = client
        .send_to_address(&address, amt, None, None, None, None, None, None)
        .map_err(|e| anyhow::anyhow!("Failed to send to address: {}", e))?;
    info!(%txid, "created funding UTXO for challenge transaction");

    let tx_hex = client
        .get_transaction(&txid, None)
        .map_err(|e| anyhow::anyhow!("Failed to get transaction: {}", e))?
        .hex;

    let tx = consensus::encode::deserialize::<Transaction>(&tx_hex)
        .map_err(|e| anyhow::anyhow!("Failed to deserialize transaction: {}", e))?;

    let vout = tx
        .output
        .iter()
        .position(|output| output.value == amt)
        .ok_or_else(|| anyhow::anyhow!("No output found with the specified amount"))?;

    Ok(OutPoint::new(txid, vout as u32))
}
