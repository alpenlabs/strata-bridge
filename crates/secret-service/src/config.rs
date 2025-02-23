use std::{net::SocketAddr, path::PathBuf};

#[derive(serde::Deserialize)]
pub struct TomlConfig {
    pub tls: TlsConfig,
    pub transport: TransportConfig,
    /// A file path to a 32 byte seed file.
    pub seed: Option<PathBuf>,
}

#[derive(serde::Deserialize)]
pub struct TransportConfig {
    /// Address to listen on for incoming connections.
    pub addr: SocketAddr,
    /// Maximum number of concurrent connections.
    pub conn_limit: Option<usize>,
}

/// Configuration for TLS.
#[derive(serde::Deserialize)]
pub struct TlsConfig {
    /// Path to the certificate file.
    pub cert: Option<PathBuf>,
    /// Path to the private key file.
    pub key: Option<PathBuf>,
    /// Path to the CA certificate to verify client certificates against.
    /// Note that S2 is insecure without client authentication.
    pub ca: Option<PathBuf>,
}
