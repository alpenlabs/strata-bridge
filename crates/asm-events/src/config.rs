//! Configuration for the ASM assignments tracker.

use std::time::Duration;

use algebra::retry::Strategy;
use serde::{Deserialize, Serialize};

/// Configuration for fetching assignment snapshots from the ASM RPC.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsmRpcConfig {
    /// ASM RPC HTTP endpoint.
    pub rpc_url: String,

    /// Timeout for each RPC request.
    pub request_timeout: Duration,

    /// Maximum number of retries per request.
    pub max_retries: usize,

    /// Initial delay for exponential backoff retries.
    pub retry_initial_delay: Duration,

    /// Maximum delay for exponential backoff retries.
    pub retry_max_delay: Duration,

    /// Exponential backoff multiplier.
    pub retry_multiplier: u64,
}

impl AsmRpcConfig {
    /// Exponential-backoff retry [`Strategy`] built from the configured retry knobs.
    pub fn retry_strategy<E: Send + Sync + 'static>(&self) -> Strategy<E> {
        Strategy::exponential_backoff(
            self.retry_initial_delay,
            self.retry_max_delay,
            self.retry_multiplier as f64,
        )
        .with_max_retries(self.max_retries)
    }
}
