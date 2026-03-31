use bitcoincore_rpc::Client;
use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};

/// Creates a Bitcoin Core RPC client using the minreq HTTP transport.
///
/// The default `simple_http` transport resolves hostnames to IP addresses and
/// sets the `Host` header to that IP, which breaks reverse-proxied endpoints
/// that route on hostname. `minreq_http` preserves the original URL/hostname.
pub(crate) fn get_btc_client(
    url: &str,
    user: String,
    pass: String,
) -> Result<Client, anyhow::Error> {
    let tp = bitcoincore_rpc::jsonrpc::minreq_http::MinreqHttpTransport::builder()
        .url(url)
        .map_err(|e| anyhow::anyhow!("invalid RPC URL: {}", e))?
        .basic_auth(user, Some(pass))
        .build();
    let jsonrpc_client = bitcoincore_rpc::jsonrpc::Client::with_transport(tp);
    Ok(Client::from_jsonrpc(jsonrpc_client))
}

pub(crate) fn get_bridge_client(url: &str) -> Result<HttpClient, anyhow::Error> {
    HttpClientBuilder::default()
        .build(url)
        .map_err(|e| anyhow::anyhow!("Failed to create bridge RPC client: {}", e))
}
