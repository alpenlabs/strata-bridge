use bitcoincore_rpc::{
    jsonrpc::{minreq_http::MinreqHttpTransport, Client as JsonrpcClient},
    Client,
};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};

/// Uses `minreq_http` transport so the original hostname is preserved in the `Host` header,
/// which is required for reverse-proxied endpoints.
pub(crate) fn get_btc_client(
    url: &str,
    user: String,
    pass: String,
) -> Result<Client, anyhow::Error> {
    let tp = MinreqHttpTransport::builder()
        .url(url)
        .map_err(|e| anyhow::anyhow!("invalid RPC URL: {}", e))?
        .basic_auth(user, Some(pass))
        .build();
    Ok(Client::from_jsonrpc(JsonrpcClient::with_transport(tp)))
}

pub(crate) fn get_bridge_client(url: &str) -> Result<HttpClient, anyhow::Error> {
    HttpClientBuilder::default()
        .build(url)
        .map_err(|e| anyhow::anyhow!("Failed to create bridge RPC client: {}", e))
}
