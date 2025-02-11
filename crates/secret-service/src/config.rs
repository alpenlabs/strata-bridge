use std::{net::SocketAddr, path::PathBuf};

#[derive(serde::Deserialize)]
pub struct TomlConfig {
    pub tls: Option<TlsConfig>,
    pub transport: TransportConfig,
    pub seed: Option<PathBuf>,
    pub db: Option<PathBuf>,
}

#[derive(serde::Deserialize)]
pub struct TransportConfig {
    pub addr: SocketAddr,
    pub conn_limit: Option<usize>,
}

#[derive(serde::Deserialize)]
pub struct TlsConfig {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
}
