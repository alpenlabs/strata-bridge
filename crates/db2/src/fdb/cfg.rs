//! Configuration for the FoundationDB client.

use std::path::PathBuf;

/// FoundationDB client configuration.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// Path to the FDB cluster file aka database config
    pub cluster_file_path: PathBuf,
    /// Optional TLS configuration.
    pub tls: Option<TlsConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            cluster_file_path: PathBuf::from(foundationdb::default_config_path()),
            tls: None,
        }
    }
}

/// See [`foundationdb::options::NetworkOption`]::TLS* and
/// <https://apple.github.io/foundationdb/tls.html> for more information.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
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
