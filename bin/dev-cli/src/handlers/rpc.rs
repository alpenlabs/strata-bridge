use bitcoincore_rpc::Client;

pub(crate) fn get_btc_client(
    url: &str,
    user: String,
    pass: String,
) -> Result<Client, anyhow::Error> {
    // Use MinreqHttpTransport instead of the default SimpleHttpTransport because
    // SimpleHttpTransport sets the Host header to the resolved IP address rather
    // than the original hostname, which breaks requests through reverse proxies.
    let transport = bitcoincore_rpc::jsonrpc::minreq_http::MinreqHttpTransport::builder()
        .url(url)
        .map_err(|e| anyhow::anyhow!("invalid RPC URL: {}", e))?
        .basic_auth(user, Some(pass))
        .build();
    let jsonrpc_client = bitcoincore_rpc::jsonrpc::Client::with_transport(transport);
    Ok(Client::from_jsonrpc(jsonrpc_client))
}
