//! Base client for interacting with the FoundationDB database.

use std::pin::Pin;

use foundationdb::{
    Database, FdbBindingError, FdbError, RangeOption, TransactOption, Transaction,
    api::{FdbApiBuilder, NetworkAutoStop},
    directory::{DirectoryError, DirectorySubspace},
    options::{NetworkOption, StreamingMode},
};
use terrors::OneOf;

use crate::fdb::{
    cfg::Config,
    dirs::Directories,
    row_spec::kv::{KVRowSpec, PackableKey, SerializableValue},
    errors::{LayerError, TransactionError},
};

/// The main entity for interacting with the FoundationDB database.
pub struct FdbClient {
    db: Database,
    dirs: Directories,
    transact_options: TransactOption,
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

        let root_directory = config.root_directory.clone();
        let dirs = db
            .run(|trx, _| {
                let root_directory = root_directory.clone();
                async move { Ok(Directories::setup(&trx, &root_directory).await) }
            })
            .await
            .map_err(OneOf::new)?
            .map_err(OneOf::new)?;
        Ok((
            Self {
                db,
                dirs,
                transact_options: config.retry.into_transact_options(),
            },
            MustDrop(guard),
        ))
    }

    /// Clears the database using the root directory.
    #[cfg(test)]
    pub async fn clear(&self) -> Result<Result<bool, DirectoryError>, FdbBindingError> {
        self.db
            .run(|trx, _| async move { Ok(self.dirs.clear(&trx).await) })
            .await
    }

    /// Creates a raw FDB [`Transaction`] for use with `_in` methods.
    ///
    /// The caller is responsible for committing (or dropping) the transaction.
    pub fn create_transaction(&self) -> Result<Transaction, FdbError> {
        self.db.create_trx()
    }

    /// Runs an async closure inside `Database::transact_boxed` with the
    /// configured retry/timeout options.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let deposit_key = DepositStateKey { deposit_idx: 0 }
    ///     .pack(client.dirs())
    ///     .map_err(LayerError::failed_to_pack_key)
    ///     .map_err(OneOf::new)?;
    /// let result = client.transact(deposit_key, |trx, data| {
    ///     Box::pin(async move {
    ///         let slice: Vec<u8> = trx.get(data.as_ref(), true).await?;
    ///         Ok(slice.to_vec())
    ///     })
    /// }).await?;
    /// ```
    async fn transact<D, T>(
        &self,
        data: D,
        txn: impl for<'a> FnMut(
            &'a Transaction,
            &'a mut D,
        ) -> Pin<
            Box<dyn Future<Output = Result<T, TransactionError>> + Send + 'a>,
        > + Send,
    ) -> Result<T, OneOf<(FdbBindingError, LayerError)>>
    where
        D: Send,
        T: Send,
    {
        self.db
            .transact_boxed(data, txn, self.transact_options.clone())
            .await
            .map_err(Into::into)
    }

    // ── Auto-transactional primitives ───────────────────────────────

    /// Basic generic set operation.
    pub async fn basic_set<RS: KVRowSpec>(
        &self,
        key: RS::Key,
        value: RS::Value,
    ) -> Result<(), OneOf<(FdbBindingError, LayerError)>> {
        let packed = key
            .pack(&self.dirs)
            .map_err(LayerError::failed_to_pack_key)
            .map_err(OneOf::new)?;
        let serialized = value
            .serialize()
            .map_err(LayerError::failed_to_serialize_value)
            .map_err(OneOf::new)?;

        self.transact((packed, serialized), |trx, data| {
            Box::pin(async move {
                trx.set(data.0.as_ref(), data.1.as_ref());
                Ok(())
            })
        })
        .await
    }

    /// Basic generic get operation.
    pub async fn basic_get<RS: KVRowSpec>(
        &self,
        key: RS::Key,
    ) -> Result<Option<RS::Value>, OneOf<(FdbBindingError, LayerError)>> {
        let packed = key
            .pack(&self.dirs)
            .map_err(LayerError::failed_to_pack_key)
            .map_err(OneOf::new)?;

        let raw = self
            .transact(packed, |trx, data| {
                Box::pin(async move {
                    let slice = trx.get(data.as_ref(), true).await?;
                    Ok(slice.map(|s| s.to_vec()))
                })
            })
            .await?;

        let Some(bytes) = raw else {
            return Ok(None);
        };
        let value = RS::Value::deserialize(&bytes)
            .map_err(LayerError::failed_to_deserialize_value)
            .map_err(OneOf::new)?;
        Ok(Some(value))
    }

    /// Basic generic range-scan that returns all key-value pairs in a subspace.
    pub async fn basic_get_all<RS: KVRowSpec>(
        &self,
        subspace_fn: impl Fn(&Directories) -> &DirectorySubspace,
    ) -> Result<Vec<(RS::Key, RS::Value)>, OneOf<(FdbBindingError, LayerError)>> {
        let subspace = subspace_fn(&self.dirs);
        let (begin, end) = subspace.range();

        let raw_kvs = self
            .transact((begin, end), |trx, data| {
                Box::pin(async move {
                    let mut opt = RangeOption::from((data.0.clone(), data.1.clone()));
                    // WantAll is a transfer hint that requests large batches
                    // up-front, but does not guarantee all results in a single
                    // response. We must still paginate via `next_range`.
                    opt.mode = StreamingMode::WantAll;
                    let mut kvs = Vec::new();
                    loop {
                        let result = trx.get_range(&opt, 1, false).await?;
                        kvs.extend(
                            result
                                .iter()
                                .map(|kv| (kv.key().to_vec(), kv.value().to_vec())),
                        );
                        match opt.next_range(&result) {
                            Some(next) => opt = next,
                            None => break,
                        }
                    }
                    Ok(kvs)
                })
            })
            .await?;

        let mut results = Vec::with_capacity(raw_kvs.len());
        for (key_bytes, value_bytes) in &raw_kvs {
            let key = RS::Key::unpack(&self.dirs, key_bytes)
                .map_err(LayerError::failed_to_unpack_key)
                .map_err(OneOf::new)?;
            let value = RS::Value::deserialize(value_bytes)
                .map_err(LayerError::failed_to_deserialize_value)
                .map_err(OneOf::new)?;
            results.push((key, value));
        }

        Ok(results)
    }

    /// Basic generic delete operation.
    pub async fn basic_delete<RS: KVRowSpec>(
        &self,
        key: RS::Key,
    ) -> Result<(), OneOf<(FdbBindingError, LayerError)>> {
        let packed = key
            .pack(&self.dirs)
            .map_err(LayerError::failed_to_pack_key)
            .map_err(OneOf::new)?;

        self.transact(packed, |trx, data| {
            Box::pin(async move {
                trx.clear(data.as_ref());
                Ok(())
            })
        })
        .await
    }

            return Ok(None);
        };
        let sig = RS::Value::deserialize(&bytes)
            .map_err(LayerError::failed_to_deserialize_value)
            .map_err(OneOf::new)?;
        Ok(Some(sig))
    }
}
