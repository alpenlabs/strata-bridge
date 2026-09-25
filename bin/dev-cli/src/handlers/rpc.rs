use std::time::Duration;

use bitcoincore_rpc::{
    jsonrpc::{minreq_http::MinreqHttpTransport, Client as JsonrpcClient},
    Client,
};
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};

/// The transport's own default; long enough for ordinary RPCs.
const DEFAULT_RPC_TIMEOUT: Duration = Duration::from_secs(15);

/// Uses `minreq_http` transport so the original hostname is preserved in the `Host` header,
/// which is required for reverse-proxied endpoints.
pub(crate) fn get_btc_client(
    url: &str,
    user: String,
    pass: String,
) -> Result<Client, anyhow::Error> {
    get_btc_client_with_timeout(url, user, pass, DEFAULT_RPC_TIMEOUT)
}

/// Same client with a per-request timeout, for calls such as `scantxoutset` that run for minutes.
pub(crate) fn get_btc_client_with_timeout(
    url: &str,
    user: String,
    pass: String,
    timeout: Duration,
) -> Result<Client, anyhow::Error> {
    let tp = MinreqHttpTransport::builder()
        .url(url)
        .map_err(|e| anyhow::anyhow!("invalid RPC URL: {}", e))?
        .basic_auth(user, Some(pass))
        .timeout(timeout)
        .build();
    Ok(Client::from_jsonrpc(JsonrpcClient::with_transport(tp)))
}

pub(crate) fn get_bridge_client(url: &str) -> Result<HttpClient, anyhow::Error> {
    HttpClientBuilder::default()
        .build(url)
        .map_err(|e| anyhow::anyhow!("Failed to create bridge RPC client: {}", e))
}
