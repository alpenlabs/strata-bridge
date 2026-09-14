//! Test utilities for wallet persistence: an in-memory [`AsyncWalletPersister`] that records
//! what was persisted and can be made to fail on demand.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use bdk_wallet::{chain::Merge, AsyncWalletPersister, ChangeSet};
use thiserror::Error;

use crate::persist::prune_stale_anchors;

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
        Box::pin(async move {
            let mut changeset = persister.aggregate();
            prune_stale_anchors(&mut changeset);
            Ok(changeset)
        })
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
