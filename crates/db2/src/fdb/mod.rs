//! Implementation of the [`BridgeDb`] trait as a FoundationDB layer.

pub mod bridge_db;
pub mod dirs;
pub mod row_spec;

use std::{fmt::Debug, path::PathBuf};

use foundationdb::{
    Database, FdbBindingError, FdbError,
    api::{FdbApiBuilder, NetworkAutoStop},
    directory::DirectoryError,
    options::NetworkOption,
};
use strata_p2p_types::P2POperatorPubKey;
use terrors::OneOf;

use crate::fdb::dirs::Directories;

/// The FoundationDB layer identifier.
pub const LAYER_ID: &[u8] = b"strata-bridge-v1";

/// The main entity for interacting with the FoundationDB database.
pub struct FdbClient {
    db: Database,
    dirs: Directories,
}

impl std::fmt::Debug for FdbClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FdbClient").finish()
    }
}

/// A struct that must be dropped before the program exits.
/// This is not required if the program aborts.
///
/// This contains the FoundationDB handle for stopping the network thread.
#[must_use = "MustDrop must be manually dropped before the program exits"]
#[allow(dead_code)]
pub struct MustDrop(NetworkAutoStop);

impl std::fmt::Debug for MustDrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MustDrop").finish()
    }
}

impl FdbClient {
    /// Sets up the database with all the correct directories.
    /// Can only be called once per process.
    pub async fn setup(
        config: Config,
        my_p2p_pubkey: P2POperatorPubKey,
    ) -> Result<(Self, MustDrop), OneOf<(FdbBindingError, FdbError, DirectoryError)>> {
        let mut network_builder = FdbApiBuilder::default()
            .build()
            .expect("fdb api initialized");

        if let Some(tls_config) = config.tls {
            network_builder = network_builder
                .set_option(NetworkOption::TLSCertPath(
                    tls_config.cert_path.to_string_lossy().to_string(),
                ))
                .map_err(OneOf::new)?
                .set_option(NetworkOption::TLSKeyPath(
                    tls_config.key_path.to_string_lossy().to_string(),
                ))
                .map_err(OneOf::new)?
                .set_option(NetworkOption::TLSCaPath(
                    tls_config.ca_path.to_string_lossy().to_string(),
                ))
                .map_err(OneOf::new)?;
            if let Some(verify_peers) = tls_config.verify_peers {
                network_builder = network_builder
                    .set_option(NetworkOption::TLSVerifyPeers(verify_peers.into_bytes()))
                    .map_err(OneOf::new)?;
            }
        }

        let guard = unsafe { network_builder.boot() }.map_err(OneOf::new)?;

        let db =
            Database::new(Some(&config.cluster_file_path.to_string_lossy())).map_err(OneOf::new)?;

        let dirs = db
            .run(|trx, _| {
                let my_p2p_pubkey = my_p2p_pubkey.clone();
                async move { Ok(Directories::setup(&trx, my_p2p_pubkey).await) }
            })
            .await
            .map_err(OneOf::new)?
            .map_err(OneOf::new)?;
        Ok((Self { db, dirs }, MustDrop(guard)))
    }

    /// Clears the database using the root directory.
    #[cfg(test)]
    pub async fn clear(&self) -> Result<Result<bool, DirectoryError>, FdbBindingError> {
        self.db
            .run(|trx, _| async move { Ok(self.dirs.clear(&trx).await) })
            .await
    }
}

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

/// See [`NetworkOption`]::TLS* and https://apple.github.io/foundationdb/tls.html
/// for more information.
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
