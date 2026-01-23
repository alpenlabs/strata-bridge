//! Base client for interacting with the FoundationDB database.

use foundationdb::{
    Database, FdbBindingError, FdbError, RetryableTransaction,
    api::{FdbApiBuilder, NetworkAutoStop},
    directory::DirectoryError,
    options::NetworkOption,
};
use strata_p2p_types::P2POperatorPubKey;
use terrors::OneOf;

use crate::fdb::{
    bridge_db::LayerError,
    cfg::Config,
    dirs::Directories,
    row_spec::{KVRowSpec, PackableKey, SerializableValue},
};

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
#[expect(dead_code)]
pub struct MustDrop(NetworkAutoStop);

impl std::fmt::Debug for MustDrop {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MustDrop").finish()
    }
}

impl FdbClient {
    /// Sets up the database with all the correct directories.
    ///
    /// # Panics
    ///
    /// This function can only be called **once per process**. Calling it a second time will panic
    /// with the message `"the fdb select api version can only be run once per process"`.
    ///
    /// This is because [`FdbApiBuilder::build()`](foundationdb::api::FdbApiBuilder::build) uses a
    /// global [`AtomicBool`](std::sync::atomic::AtomicBool) to ensure the FDB API version selection
    /// and network initialization only happens once. If you need multiple database connections,
    /// reuse the [`FdbClient`] instance returned from the first call.
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

    /// Basic generic set operation.
    pub async fn basic_set<RS: KVRowSpec>(
        &self,
        key: RS::Key,
        value: RS::Value,
    ) -> Result<(), OneOf<(FdbBindingError, LayerError)>> {
        let key = &key
            .pack(&self.dirs)
            .map_err(LayerError::failed_to_pack_key)
            .map_err(OneOf::new)?;
        let value = &value
            .serialize()
            .map_err(LayerError::failed_to_serialize_value)
            .map_err(OneOf::new)?;

        let trx = |trx: RetryableTransaction, _maybe_committed| async move {
            trx.set(key.as_ref(), value.as_ref());
            Ok(())
        };
        self.db.run(trx).await.map_err(OneOf::new)
    }

    /// Basic generic get operation.
    pub async fn basic_get<RS: KVRowSpec>(
        &self,
        key: RS::Key,
    ) -> Result<Option<RS::Value>, OneOf<(FdbBindingError, LayerError)>> {
        let key = key
            .pack(&self.dirs)
            .map_err(LayerError::failed_to_pack_key)
            .map_err(OneOf::new)?;

        let trx = |trx: RetryableTransaction, _maybe_committed| {
            let key = key.clone();
            async move { Ok(trx.get(key.as_ref(), true).await?) }
        };
        let Some(bytes) = self.db.run(trx).await.map_err(OneOf::new)? else {
            return Ok(None);
        };
        let sig = RS::Value::deserialize(&bytes)
            .map_err(LayerError::failed_to_deserialize_value)
            .map_err(OneOf::new)?;
        Ok(Some(sig))
    }
}
