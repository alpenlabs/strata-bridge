//! Configuration for the FoundationDB client.

use std::path::PathBuf;

/// FoundationDB client configuration.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// Path to the FDB cluster file aka database config
    pub cluster_file_path: PathBuf,
    /// Name of the root directory in FDB's directory layer.
    /// Defaults to "strata-bridge-v1".
    #[serde(default = "default_root_directory")]
    pub root_directory: String,
    /// Optional TLS configuration.
    pub tls: Option<TlsConfig>,
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
        }
    }
}

/// See [`foundationdb::options::NetworkOption`]::TLS* and
/// <https://apple.github.io/foundationdb/tls.html> for more information.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
