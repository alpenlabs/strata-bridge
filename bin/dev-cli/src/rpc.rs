use anyhow::{Context, Result};

use crate::cli::BtcArgs;

/// Creates a `bitcoincore_rpc::Client` using the `minreq` HTTP transport.
///
/// The default `simple_http` transport resolves hostnames to IP addresses and
/// sends the IP in the HTTP `Host` header, which breaks routing when bitcoind
/// sits behind a reverse proxy that dispatches on hostname. `minreq` sends the
/// original hostname, avoiding 404s from the proxy.
pub(crate) fn new_btc_client(args: &BtcArgs) -> Result<bitcoincore_rpc::Client> {
    let tp = jsonrpc::minreq_http::Builder::new()
        .url(&args.url)
        .context("invalid btc-url")?
        .basic_auth(args.user.clone(), Some(args.pass.clone()))
        .build();

    let jsonrpc_client = jsonrpc::Client::with_transport(tp);
    Ok(bitcoincore_rpc::Client::from_jsonrpc(jsonrpc_client))
}
