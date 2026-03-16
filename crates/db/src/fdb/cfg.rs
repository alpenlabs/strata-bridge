//! Configuration for the FoundationDB client.

use std::{path::PathBuf, time::Duration};

use foundationdb::TransactOption;
use serde::{Deserialize, Serialize};

/// FoundationDB client configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Config {
    /// Path to the FDB cluster file aka database config
    pub cluster_file_path: PathBuf,
    /// Name of the root directory in FDB's directory layer.
    /// Defaults to "strata-bridge-v1".
    #[serde(default = "default_root_directory")]
    pub root_directory: String,
    /// Optional TLS configuration.
    pub tls: Option<TlsConfig>,
    /// Transaction retry options.
    pub retry: RetryConfig,
}

/// Default root directory name for FDB's directory layer.
fn default_root_directory() -> String {
    "strata-bridge-v1".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cluster_file_path: PathBuf::from(foundationdb::default_config_path()),
            root_directory: default_root_directory(),
            tls: None,
            retry: RetryConfig::default(),
        }
    }
}

/// See [`foundationdb::options::NetworkOption`]::TLS* and
/// <https://apple.github.io/foundationdb/tls.html> for more information.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the TLS certificate file.
    pub cert_path: PathBuf,
    /// Path to the TLS key file.
    pub key_path: PathBuf,
    /// Path to the TLS CA bundle file.
    pub ca_path: PathBuf,
    /// Verification string. Look at Apple's docs for more info.
    pub verify_peers: Option<String>,
}

const DEFAULT_RETRY_LIMIT: u32 = 5;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Transaction retry configuration for FDB operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retries before giving up. `None` = unlimited.
    pub retry_limit: Option<u32>,
    /// Maximum total transaction duration in seconds. `None` = unlimited.
    pub timeout: Option<Duration>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            retry_limit: Some(DEFAULT_RETRY_LIMIT),
            timeout: Some(DEFAULT_TIMEOUT),
        }
    }
}

impl RetryConfig {
    /// Converts to `TransactOption` with `is_idempotent: true` (hardcoded).
    pub const fn into_transact_options(self) -> TransactOption {
        TransactOption {
            retry_limit: self.retry_limit,
            time_out: self.timeout,

            // always `true` because all FdbClient operations are blob set/get/clear, which are
            // inherently idempotent.
            is_idempotent: true,
        }
    }
}
