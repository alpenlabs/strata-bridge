//! ASM RPC HTTP client initialization.

use jsonrpsee::http_client::{HttpClient, HttpClientBuilder};
use strata_bridge_asm_events::config::AsmRpcConfig;

/// Build a [`jsonrpsee`] HTTP client targeting the ASM RPC service.
///
/// The returned client is shared between the
/// [`AsmEventFeed`](strata_bridge_asm_events::client::AsmEventFeed) background fetcher and any
/// executor that needs to query ASM RPC directly via `OutputHandles`.
///
/// # Panics
///
/// Panics if the configured URL cannot be used to construct an HTTP client.
pub(crate) fn init_asm_rpc_client(config: &AsmRpcConfig) -> HttpClient {
    HttpClientBuilder::default()
        .build(&config.rpc_url)
        .unwrap_or_else(|e| {
            panic!(
                "failed to build ASM HTTP client for {}: {e}",
                config.rpc_url
            )
        })
}
