//! Configuration structures for ASM RPC server

use std::path::PathBuf;

use btc_tracker::config::BtcNotifyConfig;
use serde::Deserialize;

/// Main configuration structure
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct AsmRpcConfig {
    /// RPC server configuration
    pub rpc: RpcConfig,
    /// Database configuration
    pub database: DatabaseConfig,
    /// Bitcoin node configuration
    pub bitcoin: BitcoinConfig,
    /// BTC tracker configuration
    pub btc_tracker: BtcNotifyConfig,
}

/// RPC server configuration
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct RpcConfig {
    /// Host address to bind to
    pub host: String,
    /// Port to listen on
    pub port: u16,
}

/// Database configuration
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct DatabaseConfig {
    /// SledDB path (directory)
    pub path: PathBuf,
}

/// Bitcoin node configuration
#[derive(Debug, Clone, Deserialize)]
pub(crate) struct BitcoinConfig {
    /// Bitcoin RPC URL
    pub rpc_url: String,
    /// Bitcoin RPC username
    pub rpc_user: String,
    /// Bitcoin RPC password
    pub rpc_password: String,
    /// Optional retry count for failed requests
    pub retry_count: Option<u64>,
    /// Optional retry interval for failed requests (in milliseconds)
    pub retry_interval: Option<u64>,
}
