//! Persistence for the operator wallets.
//!
//! Both wallets are BDK [`PersistedWallet`]s behind the [`WalletStore`] seam. [`load_or_create`]
//! is the shared entry point: load and validate persisted state, or create a fresh wallet when the
//! store is empty. [`SqliteStore`] is the durable store; the `test_utils` module (feature
//! `test-utils`) holds the in-memory one for tests.

pub mod sqlite;
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

use bdk_wallet::{
    bitcoin::{constants::genesis_block, Network},
    chain::local_chain::CannotConnectError,
    descriptor::{DescriptorError, ExtendedDescriptor},
    KeychainKind, LoadError, LoadWithPersistError, Update, Wallet,
};
pub use bdk_wallet::{chain::BlockId, AsyncWalletPersister, ChangeSet, PersistedWallet};
pub use sqlite::{SqliteStore, SqliteStoreError, WalletKind};
use thiserror::Error;
use tracing::info;

use crate::sync::Backend;

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
    /// The descriptor is not valid for BDK.
    #[error("wallet descriptor: {0}")]
    Descriptor(DescriptorError),
    /// The store reported no data straight after acknowledging the initial write.
    #[error("wallet store reported no data after the initial write was acknowledged")]
    StoreDroppedWrite,
    /// The backend's chain is shorter than the persisted tip.
    #[error("node is at height {height}, behind the persisted wallet tip {tip}")]
    BackendBehindTip {
        /// Height of the persisted tip.
        tip: u32,
        /// Height of the backend's best chain.
        height: u32,
    },
    /// The backend could not be asked for its height.
    #[error("checking the persisted tip against the node: {0:?}")]
    Backend(crate::sync::SyncError),
    /// The bootstrap checkpoint is not above genesis.
    #[error("bootstrap checkpoint at height {0} must be above genesis")]
    BootstrapHeight(u32),
    /// The bootstrap checkpoint could not be connected to genesis.
    #[error("bootstrap checkpoint does not connect to genesis: {0}")]
    Bootstrap(CannotConnectError),
}

impl<E: std::error::Error + 'static> From<LoadWithPersistError<E>> for InitError<E> {
    fn from(e: LoadWithPersistError<E>) -> Self {
        match e {
            LoadWithPersistError::Persist(e) => Self::Store(e),
            LoadWithPersistError::InvalidChangeSet(e) => Self::InvalidState(Box::new(e)),
        }
    }
}

/// Loads the wallet for `descriptor` from `store`, or creates it when the store is empty.
///
/// Loading verifies network, genesis hash, and both keychains' descriptor identity; a mismatch
/// fails without touching the store. Creating persists the descriptor, network, and genesis
/// block, then seeds the local chain with `bootstrap_checkpoint` if given, so the first sync
/// starts above it. The checkpoint is ignored on load: persisted state wins.
pub async fn load_or_create<P: WalletStore>(
    store: &mut P,
    descriptor: ExtendedDescriptor,
    network: Network,
    bootstrap_checkpoint: Option<BlockId>,
) -> Result<PersistedWallet<P>, InitError<P::Error>> {
    let load_params = || {
        Wallet::load()
            .descriptor(KeychainKind::External, Some(descriptor.clone()))
            .descriptor(KeychainKind::Internal, Option::<ExtendedDescriptor>::None)
            .check_network(network)
            .check_genesis_hash(genesis_block(network).block_hash())
    };
    if let Some(wallet) = PersistedWallet::load_async(store, load_params()).await? {
        info!(
            tip_height = wallet.latest_checkpoint().height(),
            "loaded persisted wallet state"
        );
        return Ok(wallet);
    }

    // Build the whole initial state in memory and commit it once. Committing the wallet and the
    // checkpoint separately would let a failure in between strand the wallet at genesis: the load
    // path wins on the next start, so the checkpoint would never be applied.
    let mut wallet = Wallet::create_single(descriptor.clone())
        .network(network)
        .create_wallet_no_persist()
        .map_err(InitError::Descriptor)?;
    if let Some(block) = bootstrap_checkpoint {
        // `push` refuses a height at or below the current tip, which is genesis here.
        let chain = wallet
            .latest_checkpoint()
            .push(block)
            .map_err(|_| InitError::BootstrapHeight(block.height))?;
        wallet
            .apply_update(Update {
                chain: Some(chain),
                ..Update::default()
            })
            .map_err(InitError::Bootstrap)?;
    }
    let changeset = wallet
        .take_staged()
        .expect("a fresh wallet always stages its descriptor and network");
    P::persist(store, &changeset)
        .await
        .map_err(InitError::Store)?;

    match bootstrap_checkpoint {
        Some(block) => info!(
            height = block.height,
            hash = %block.hash,
            "created wallet seeded with bootstrap checkpoint"
        ),
        None => info!("created wallet at genesis"),
    }
    PersistedWallet::load_async(store, load_params())
        .await?
        .ok_or(InitError::StoreDroppedWrite)
}

/// Fails when the backend's chain is shorter than the wallet's tip.
///
/// A reorg is not a problem on its own: the emitter walks back to a block the backend still has
/// and re-emits from there. It can only do that while the backend has blocks above that one, so a
/// backend shorter than the stored tip, as after restoring an older node data directory, leaves
/// the wallet's extra blocks in place with their transactions still looking confirmed.
pub async fn ensure_backend_not_behind<P: WalletStore>(
    backend: &Backend,
    wallet: &PersistedWallet<P>,
) -> Result<(), InitError<P::Error>> {
    let tip = wallet.latest_checkpoint().height();
    let height = backend.height().await.map_err(InitError::Backend)?;
    if height >= tip {
        return Ok(());
    }
    Err(InitError::BackendBehindTip { tip, height })
}

#[cfg(test)]
mod tests {
    use bdk_wallet::{
        bitcoin::{
            hashes::Hash,
            secp256k1::{Keypair, Secp256k1, SecretKey},
            BlockHash, XOnlyPublicKey,
        },
        chain::Merge,
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
        bootstrap: Option<BlockId>,
    ) -> Result<PersistedWallet<MemoryStore>, InitError<MemoryStoreError>> {
        load_or_create(store, tr_descriptor(seed), network, bootstrap).await
    }

    #[tokio::test]
    async fn create_then_load_persists_once() {
        let mut store = MemoryStore::new();
        let wallet = open(&mut store, 1, Network::Regtest, None)
            .await
            .expect("create");
        assert_eq!(wallet.latest_checkpoint().height(), 0);
        assert_eq!(store.persist_calls(), 1, "create persists once");
        drop(wallet);

        let wallet = open(&mut store, 1, Network::Regtest, None)
            .await
            .expect("load");
        assert_eq!(wallet.latest_checkpoint().height(), 0);
        assert_eq!(store.persist_calls(), 1, "loading never writes");
    }

    #[tokio::test]
    async fn wrong_network_is_rejected_and_the_store_is_untouched() {
        let mut store = MemoryStore::new();
        open(&mut store, 1, Network::Regtest, None)
            .await
            .expect("create");

        let err = open(&mut store, 1, Network::Signet, None)
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
        open(&mut store, 1, Network::Regtest, None)
            .await
            .expect("create");

        let err = open(&mut store, 2, Network::Regtest, None)
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

    #[tokio::test]
    async fn an_unexpected_change_descriptor_is_rejected() {
        let mut store = MemoryStore::new();
        open(&mut store, 1, Network::Regtest, None)
            .await
            .expect("create");

        // A store carrying the expected external descriptor plus a change keychain must fail:
        // these wallets never write one, and change would otherwise be derived from it.
        let with_change_keychain = ChangeSet {
            change_descriptor: Some(tr_descriptor(2)),
            ..ChangeSet::default()
        };
        MemoryStore::persist(&mut store, &with_change_keychain)
            .await
            .unwrap();

        let err = open(&mut store, 1, Network::Regtest, None)
            .await
            .expect_err("unexpected change keychain");
        assert!(
            matches!(
                &err,
                InitError::InvalidState(e) if matches!(
                    **e,
                    LoadError::Mismatch(LoadMismatch::Descriptor {
                        keychain: KeychainKind::Internal,
                        ..
                    })
                )
            ),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn store_failure_on_create_surfaces_as_store_error() {
        let mut store = MemoryStore::new();
        store.fail_on_persist_call(1);
        let err = open(&mut store, 1, Network::Regtest, None)
            .await
            .expect_err("injected");
        assert!(matches!(
            err,
            InitError::Store(MemoryStoreError { call: 1 })
        ));
        assert!(store.aggregate().is_empty());
    }

    #[tokio::test]
    async fn bootstrap_checkpoint_seeds_the_chain_and_is_ignored_on_load() {
        let mut store = MemoryStore::new();
        let block = BlockId {
            height: 500,
            hash: BlockHash::from_byte_array([7; 32]),
        };
        let wallet = open(&mut store, 1, Network::Regtest, Some(block))
            .await
            .expect("create with bootstrap");
        assert_eq!(wallet.latest_checkpoint().block_id(), block);
        assert_eq!(
            store.persist_calls(),
            1,
            "wallet and checkpoint commit together"
        );
        drop(wallet);

        // A different checkpoint on load changes nothing: persisted state wins.
        let other = BlockId {
            height: 900,
            hash: BlockHash::from_byte_array([9; 32]),
        };
        let wallet = open(&mut store, 1, Network::Regtest, Some(other))
            .await
            .expect("load");
        assert_eq!(wallet.latest_checkpoint().block_id(), block);
        assert_eq!(store.persist_calls(), 1, "loading never writes");
    }

    #[tokio::test]
    async fn a_bootstrap_create_is_a_single_commit() {
        let block = BlockId {
            height: 500,
            hash: BlockHash::from_byte_array([7; 32]),
        };

        // A failed create leaves nothing behind, so the retry applies the checkpoint. Committing
        // the wallet and the checkpoint separately would instead strand a genesis-only wallet that
        // the load path prefers from then on, and the checkpoint would never be applied.
        let mut store = MemoryStore::new();
        store.fail_on_persist_call(1);
        open(&mut store, 1, Network::Regtest, Some(block))
            .await
            .expect_err("injected");
        assert!(
            store.aggregate().is_empty(),
            "nothing to load after a failed create"
        );
        let wallet = open(&mut store, 1, Network::Regtest, Some(block))
            .await
            .expect("retry");
        assert_eq!(wallet.latest_checkpoint().block_id(), block);

        // There is no second commit to fail: the whole initial state goes in one call.
        let mut store = MemoryStore::new();
        store.fail_on_persist_call(2);
        let wallet = open(&mut store, 1, Network::Regtest, Some(block))
            .await
            .expect("create must not need a second commit");
        assert_eq!(wallet.latest_checkpoint().block_id(), block);
        assert_eq!(store.persist_calls(), 1);
    }

    #[tokio::test]
    async fn bootstrap_checkpoint_at_genesis_height_is_rejected() {
        let mut store = MemoryStore::new();
        let genesis_height = BlockId {
            height: 0,
            hash: BlockHash::from_byte_array([1; 32]),
        };
        let err = open(&mut store, 1, Network::Regtest, Some(genesis_height))
            .await
            .expect_err("height zero cannot sit above genesis");
        assert!(matches!(err, InitError::BootstrapHeight(0)));
    }
}
