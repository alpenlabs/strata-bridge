//! Configuration structures for ASM RPC server

use std::{path::PathBuf, time::Duration};

use serde::{Deserialize, Serialize};

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct AsmRpcConfig {
    /// RPC server configuration
    pub rpc: RpcConfig,
    /// Database configuration
    pub database: DatabaseConfig,
    /// Bitcoin node configuration
    pub bitcoin: BitcoinConfig,
}

/// RPC server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct RpcConfig {
    /// Host address to bind to
    pub host: String,
    /// Port to listen on
    pub port: u16,
}

/// Database configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DatabaseConfig {
    /// SledDB path (directory)
    pub path: PathBuf,
    /// Optional number of threads for database operations.
    pub num_threads: Option<usize>,
    /// Optional number of retries for failed database operations.
    pub retry_count: Option<u16>,
    /// Optional number between retries for failed database operations.
    pub delay: Option<Duration>,
}

/// Bitcoin node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct BitcoinConfig {
    /// Bitcoin RPC URL
    pub rpc_url: String,
    /// Bitcoin RPC username
    pub rpc_user: String,
    /// Bitcoin RPC password
    pub rpc_password: String,
    /// Optional retry count for failed requests
    pub retry_count: Option<u64>,
    /// Optional retry interval
    pub retry_interval: Option<Duration>,
    /// Connection string used in `bitcoin.conf => zmqpubrawblock`.
    // TODO: <https://atlassian.alpenlabs.net/browse/STR-2662>
    // Support `hashblock_connection_string`; ASM runner already uses btc-client to fetch full
    // blocks, but `BlockEvent` is only emitted on the rawblock connection today.
    pub rawblock_connection_string: String,
}
