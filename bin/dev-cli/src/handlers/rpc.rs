use bitcoincore_rpc::{Auth, Client};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};

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

pub(crate) fn get_bridge_client(url: &str) -> Result<HttpClient, anyhow::Error> {
    HttpClientBuilder::default()
        .build(url)
        .map_err(|e| anyhow::anyhow!("Failed to create bridge RPC client: {}", e))
}
