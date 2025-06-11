use bitcoincore_rpc::{Auth, Client};
use jsonrpsee::http_client::HttpClient;

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

    Ok(btc_client)
}
