//! Configuration for the Secret Service.

use std::{net::SocketAddr, path::PathBuf};

use bitcoin::Network;
use serde::Deserialize;

/// Configuration for the Secret Service.
#[derive(Debug, Deserialize)]
pub struct Config {
    /// Configuration for TLS.
    pub tls: TlsConfig,

    /// Configuration for the transport layer.
    pub transport: TransportConfig,

    /// A file path to a 32-byte seed file.
    pub seed: Option<PathBuf>,

    /// Which bitcoin network to use
    pub network: Option<Network>,
}

/// Configuration for the transport layer.
#[derive(Debug, Deserialize)]
pub struct TransportConfig {
    /// Address to listen on for incoming connections.
    pub addr: SocketAddr,
    /// Maximum number of concurrent connections.
    pub conn_limit: Option<usize>,
}

/// Configuration for TLS.
#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    /// Path to the certificate file.
    pub cert: Option<PathBuf>,
    /// Path to the private key file.
    pub key: Option<PathBuf>,
    /// Path to the CA certificate to verify client certificates against.
    /// Note that Secret Service is insecure without client authentication.
    pub ca: Option<PathBuf>,
}
