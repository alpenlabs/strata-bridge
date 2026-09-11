//! Test utilities for wallet persistence: an in-memory [`AsyncWalletPersister`] that records
//! what was persisted and can be made to fail on demand.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use bdk_wallet::{chain::Merge, AsyncWalletPersister, ChangeSet};
use thiserror::Error;

/// In-memory store. Clones share one store, so a test can rebuild a wallet from a clone to
/// simulate a restart. Records every persisted changeset and can fail one chosen `persist` call.
#[derive(Debug, Clone, Default)]
pub struct MemoryStore {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug, Default)]
struct Inner {
    /// Merge of every persisted changeset; what `initialize` returns.
    aggregate: ChangeSet,
    /// Every successfully persisted changeset, in call order.
    history: Vec<ChangeSet>,
    /// `persist` calls so far, including failed ones.
    persist_calls: usize,
    /// One-based index of the `persist` call that fails. Cleared once it fires.
    fail_on_call: Option<usize>,
}

/// Error injected by [`MemoryStore::fail_on_persist_call`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("memory store: injected failure on persist call {call}")]
pub struct MemoryStoreError {
    /// One-based index of the persist call that failed.
    pub call: usize,
}

impl MemoryStore {
    /// Creates an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Makes the `call`-th (one-based) future `persist` call fail, once.
    pub fn fail_on_persist_call(&self, call: usize) {
        self.lock().fail_on_call = Some(call);
    }

    /// `persist` calls so far, including a failed one.
    pub fn persist_calls(&self) -> usize {
        self.lock().persist_calls
    }

    /// Every successfully persisted changeset, in call order.
    pub fn history(&self) -> Vec<ChangeSet> {
        self.lock().history.clone()
    }

    /// Merge of everything persisted so far, i.e. what `initialize` returns.
    pub fn aggregate(&self) -> ChangeSet {
        self.lock().aggregate.clone()
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, MemoryStoreError>> + Send + 'a>>;

impl AsyncWalletPersister for MemoryStore {
    type Error = MemoryStoreError;

    fn initialize<'a>(persister: &'a mut Self) -> StoreFuture<'a, ChangeSet>
    where
        Self: 'a,
    {
        Box::pin(async move { Ok(persister.aggregate()) })
    }

    fn persist<'a>(persister: &'a mut Self, changeset: &'a ChangeSet) -> StoreFuture<'a, ()>
    where
        Self: 'a,
    {
        Box::pin(async move {
            let mut inner = persister.lock();
            inner.persist_calls += 1;
            let call = inner.persist_calls;
            if inner.fail_on_call == Some(call) {
                inner.fail_on_call = None;
                return Err(MemoryStoreError { call });
            }
            inner.aggregate.merge(changeset.clone());
            inner.history.push(changeset.clone());
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use bdk_wallet::{
        bitcoin::{hashes::Hash, BlockHash},
        chain::local_chain,
    };

    use super::*;

    fn chain_changeset(entries: impl IntoIterator<Item = (u32, Option<u8>)>) -> ChangeSet {
        let blocks = entries
            .into_iter()
            .map(|(h, b)| (h, b.map(|b| BlockHash::from_byte_array([b; 32]))))
            .collect();
        ChangeSet {
            local_chain: local_chain::ChangeSet { blocks },
            ..ChangeSet::default()
        }
    }

    #[tokio::test]
    async fn aggregates_and_records_history() {
        let mut store = MemoryStore::new();
        let first = chain_changeset([(0, Some(0)), (1, Some(1))]);
        let second = chain_changeset([(2, Some(2))]);

        MemoryStore::persist(&mut store, &first).await.unwrap();
        MemoryStore::persist(&mut store, &second).await.unwrap();

        let loaded = MemoryStore::initialize(&mut store).await.unwrap();
        assert_eq!(loaded.local_chain.blocks.len(), 3);
        assert_eq!(store.history(), vec![first, second]);
        assert_eq!(store.persist_calls(), 2);
    }

    #[tokio::test]
    async fn injected_failure_fires_once_and_persists_nothing() {
        let mut store = MemoryStore::new();
        store.fail_on_persist_call(1);
        let cs = chain_changeset([(0, Some(0))]);

        let err = MemoryStore::persist(&mut store, &cs).await.unwrap_err();
        assert_eq!(err, MemoryStoreError { call: 1 });
        assert!(store.history().is_empty(), "failed call must not persist");
        assert!(store.aggregate().is_empty());

        MemoryStore::persist(&mut store, &cs).await.unwrap();
        assert_eq!(store.history().len(), 1);
        assert_eq!(store.persist_calls(), 2);
    }

    #[tokio::test]
    async fn clones_share_storage() {
        let mut store = MemoryStore::new();
        let twin = store.clone();
        MemoryStore::persist(&mut store, &chain_changeset([(0, Some(0))]))
            .await
            .unwrap();
        assert_eq!(twin.history().len(), 1);
    }
}
