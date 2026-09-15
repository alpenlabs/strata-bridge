//! Persistence for the operator wallets.
//!
//! [`WalletStore`] is the seam a wallet persists through; [`load_or_create`] is the shared entry
//! point that loads and validates persisted state, or creates a fresh wallet when the store is
//! empty. The `test_utils` module (feature `test-utils`) holds the in-memory store for tests.

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

use bdk_wallet::{
    bitcoin::{constants::genesis_block, Network},
    descriptor::{DescriptorError, ExtendedDescriptor},
    CreateWithPersistError, KeychainKind, LoadError, LoadWithPersistError, Wallet,
};
pub use bdk_wallet::{AsyncWalletPersister, ChangeSet, PersistedWallet};
use thiserror::Error;
use tracing::info;

/// [`AsyncWalletPersister`] whose errors can be boxed and which can live behind an
/// `Arc<RwLock<_>>` across tasks. Blanket-implemented; implement the BDK trait and this follows.
pub trait WalletStore:
    AsyncWalletPersister<Error: std::error::Error + Send + Sync + 'static> + Send + Sync
{
}

impl<P> WalletStore for P where
    P: AsyncWalletPersister<Error: std::error::Error + Send + Sync + 'static> + Send + Sync
{
}

/// Errors from [`load_or_create`]. None of them modifies the store.
#[derive(Debug, Error)]
pub enum InitError<E: std::error::Error + 'static> {
    /// The store failed to read or write.
    #[error("wallet store: {0}")]
    Store(E),
    /// Persisted state is for another network, genesis, or descriptor, or is incomplete.
    #[error("persisted wallet state is invalid for this wallet: {0}")]
    InvalidState(Box<LoadError>),
    /// The store was empty on load but not on create: a concurrent writer.
    #[error("wallet store reported existing data while creating a fresh wallet")]
    DataAlreadyExists,
    /// The descriptor is not valid for BDK.
    #[error("wallet descriptor: {0}")]
    Descriptor(DescriptorError),
}

impl<E: std::error::Error + 'static> From<LoadWithPersistError<E>> for InitError<E> {
    fn from(e: LoadWithPersistError<E>) -> Self {
        match e {
            LoadWithPersistError::Persist(e) => Self::Store(e),
            LoadWithPersistError::InvalidChangeSet(e) => Self::InvalidState(Box::new(e)),
        }
    }
}

impl<E: std::error::Error + 'static> From<CreateWithPersistError<E>> for InitError<E> {
    fn from(e: CreateWithPersistError<E>) -> Self {
        match e {
            CreateWithPersistError::Persist(e) => Self::Store(e),
            CreateWithPersistError::DataAlreadyExists(_) => Self::DataAlreadyExists,
            CreateWithPersistError::Descriptor(e) => Self::Descriptor(e),
        }
    }
}

/// Loads the wallet for `descriptor` from `store`, or creates it when the store is empty.
///
/// Loading verifies network, genesis hash, and descriptor identity; a mismatch fails without
/// touching the store. Creating persists the descriptor, network, and genesis block.
pub async fn load_or_create<P: WalletStore>(
    store: &mut P,
    descriptor: ExtendedDescriptor,
    network: Network,
) -> Result<PersistedWallet<P>, InitError<P::Error>> {
    let load_params = Wallet::load()
        .descriptor(KeychainKind::External, Some(descriptor.clone()))
        .check_network(network)
        .check_genesis_hash(genesis_block(network).block_hash());
    if let Some(wallet) = PersistedWallet::load_async(store, load_params).await? {
        info!(
            tip_height = wallet.latest_checkpoint().height(),
            "loaded persisted wallet state"
        );
        return Ok(wallet);
    }

    let create_params = Wallet::create_single(descriptor).network(network);
    let wallet = PersistedWallet::create_async(store, create_params).await?;
    info!("created wallet at genesis");
    Ok(wallet)
}

#[cfg(test)]
mod tests {
    use bdk_wallet::{
        bitcoin::{
            secp256k1::{Keypair, Secp256k1, SecretKey},
            XOnlyPublicKey,
        },
        descriptor, LoadMismatch,
    };

    use super::*;
    use crate::persist::test_utils::{MemoryStore, MemoryStoreError};

    fn xonly(seed: u8) -> XOnlyPublicKey {
        let secret = SecretKey::from_slice(&[seed; 32]).expect("valid scalar");
        Keypair::from_secret_key(&Secp256k1::new(), &secret)
            .x_only_public_key()
            .0
    }

    fn tr_descriptor(seed: u8) -> ExtendedDescriptor {
        descriptor!(tr(xonly(seed))).expect("valid descriptor").0
    }

    async fn open(
        store: &mut MemoryStore,
        seed: u8,
        network: Network,
    ) -> Result<PersistedWallet<MemoryStore>, InitError<MemoryStoreError>> {
        load_or_create(store, tr_descriptor(seed), network).await
    }

    #[tokio::test]
    async fn create_then_load_persists_once() {
        let mut store = MemoryStore::new();
        let wallet = open(&mut store, 1, Network::Regtest).await.expect("create");
        assert_eq!(wallet.latest_checkpoint().height(), 0);
        assert_eq!(store.persist_calls(), 1, "create persists once");
        drop(wallet);

        let wallet = open(&mut store, 1, Network::Regtest).await.expect("load");
        assert_eq!(wallet.latest_checkpoint().height(), 0);
        assert_eq!(store.persist_calls(), 1, "loading never writes");
    }

    #[tokio::test]
    async fn wrong_network_is_rejected_and_the_store_is_untouched() {
        let mut store = MemoryStore::new();
        open(&mut store, 1, Network::Regtest).await.expect("create");

        let err = open(&mut store, 1, Network::Signet)
            .await
            .expect_err("network mismatch");
        assert!(
            matches!(
                &err,
                InitError::InvalidState(e)
                    if matches!(**e, LoadError::Mismatch(LoadMismatch::Network { .. }))
            ),
            "got {err:?}"
        );
        assert_eq!(store.persist_calls(), 1, "rejected load must not write");
    }

    #[tokio::test]
    async fn wrong_descriptor_is_rejected_and_the_store_is_untouched() {
        let mut store = MemoryStore::new();
        open(&mut store, 1, Network::Regtest).await.expect("create");

        let err = open(&mut store, 2, Network::Regtest)
            .await
            .expect_err("descriptor mismatch");
        assert!(
            matches!(
                &err,
                InitError::InvalidState(e)
                    if matches!(**e, LoadError::Mismatch(LoadMismatch::Descriptor { .. }))
            ),
            "got {err:?}"
        );
        assert_eq!(store.persist_calls(), 1);
    }
}
