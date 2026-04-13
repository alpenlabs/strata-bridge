use bitcoincore_rpc::{Auth, Client, RpcApi};
use jsonrpsee::http_client::HttpClient;
use tracing::info;

pub(crate) fn get_bridge_client(bridge_node_url: &str) -> Result<HttpClient, anyhow::Error> {
    jsonrpsee::http_client::HttpClient::builder()
        .build(bridge_node_url)
        .map_err(|e| anyhow::anyhow!("Failed to create bridge RPC client: {}", e))
}

pub(crate) fn get_btc_client(
    url: &str,
    user: String,
    pass: String,
) -> Result<Client, anyhow::Error> {
    let btc_auth = Auth::UserPass(user, pass);
    let btc_client = Client::new(url, btc_auth)
        .map_err(|e| anyhow::anyhow!("Failed to create RPC client: {}", e))?;

    let btc_info = btc_client
        .get_blockchain_info()
        .map_err(|e| anyhow::anyhow!("Failed to connect to Bitcoin RPC: {}", e))?;
    info!(chain=%btc_info.chain, blocks=btc_info.blocks, "Connected to Bitcoin RPC");

    let balance = btc_client
        .get_balance(None, None)
        .map_err(|e| anyhow::anyhow!("Failed to get balance from Bitcoin RPC: {}", e))?;
    info!(balance=%balance, "Bitcoin RPC wallet balance");

    Ok(btc_client)
}
