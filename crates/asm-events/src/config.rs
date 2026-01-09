//! Configuration for the ASM assignments tracker.

use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Configuration for fetching assignment snapshots from the ASM RPC.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AsmRpcConfig {
    /// ASM RPC HTTP endpoint.
    pub rpc_url: String,

    /// Timeout for each RPC request.
    pub request_timeout: Duration,

    /// Maximum number of retries per request. `None` means retry indefinitely.
    pub max_retries: Option<usize>,

    /// Initial delay for exponential backoff retries.
    pub retry_initial_delay: Duration,

    /// Maximum delay for exponential backoff retries.
    pub retry_max_delay: Duration,

    /// Exponential backoff multiplier.
    pub retry_multiplier: f64,
}
