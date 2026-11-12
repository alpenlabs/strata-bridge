//! Test utilities for wallet persistence: an in-memory [`AsyncWalletPersister`] that records
//! what was persisted and can be made to fail on demand.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
};

use bdk_wallet::{bitcoin::OutPoint, chain::Merge, AsyncWalletPersister, ChangeSet};
use thiserror::Error;

use crate::{
    leases::{Lease, LeaseOwner, LeaseSet},
    persist::prune_stale_anchors,
};

/// A lease on `outpoints` from a lease set of its own, for a test that needs a lease without a
/// wallet.
pub fn lease_on(outpoints: Vec<OutPoint>) -> Lease {
    Arc::new(LeaseSet::default()).take(outpoints, LeaseOwner::Rehydrated)
}

/// A lease that holds nothing, for a test double that must hand out a lease.
pub fn empty_lease() -> Lease {
    lease_on(Vec::new())
}

/// Throwaway 2048-bit RSA private key (PKCS#8 PEM), not a secret, for a Fireblocks signer in a
/// test.
#[cfg(feature = "fireblocks")]
pub const TEST_RSA_PRIVATE_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCMNfum0ipMfWIS
eowAEix26JaYdgLNzn/xQUMBNmRJFe4Fx308Du/8UJcqrl1L2daqU3oAvtZxl7jI
S9qXHGbCbGNyAypL/BR69xKVZJi8FGH6rJyN+dI1xW/CbnOo9w96ZotxM43XGofF
0zOd3pAfICrH5hmCvx+bRH7zOYJAKve6G8lZGS6F57spgv2Ez+3Y0rXTkTJoEw47
X6kdsouRZzD2KxMzzZGtAxG2mIzjozQCokb8RBxpQeytQwg4Tnm5uLIr/IrKOs9q
XXaHyiO+hvj3iBzQbb4vPdIOh719vmAlmZOskDRKe9Y2lVJqlLZJohTirRf2eRb1
lkJE+PdTAgMBAAECggEANnHl6Nb2TuJnOUa143crJfdWNxioKRO1MdEGPEvLMGgg
F8Vpl28zeFYxBQVVPBV4WoZ0uyJfshdYzQpLdN819exRx118SKo3p7IWWMWJ24rM
qyLo3eay3mdu6OCr7+IT9BMqtYfv3aWzMDm9cuGQNE3w3tO2d0NQ+iFkbH0Z22Fg
wRP+QyTXEBK/k+lIsCPAmiytjUPwOeO6p3dfbyGKtBE894oZ8d/LH03FV6vPRRYY
rBDmN3MOO6jZ3fg2MsllbFwDmqX1UQT9+5EWdZAwXYm/nv544aGZL/P7hMjSUdev
9xi8mMu9pG41+6/HpVe7hCBeJoHJodCrO1hcFX8xNQKBgQDDUJThjwH89HnqyBr4
RBcAc8eDquIRgV2CyJ5oU5WGs0ErLf8HAklXo9MDf1dMBGKY1NNfhVx84PZFCQiG
lb3H3CevRm+a1HE10XyZWCD47g1VPk3SFQsRUVtaRdwxd9bXF6ACBaQ3ugkXw+N0
5bMihRfBdw00zuZE3QzdrHv8nwKBgQC3xmoJQtlmn3gMTGnZsNdrnMVOGEWmPfYB
eYt4hjjI9QZE8q2MlqhdmGlQGzo+FOQhnjAEGwDQwGRD5eV4snfn7tL/R1VmJld9
Wr1sjE6/c6O9+0SA6/AfyUvNMljbR8ygyDwyQdXQ5OOwLfsChZYoRJlut9yBMZ61
6K1zugTUzQKBgAg/C7omPpA+hjM6daELxujW+pJ9kYPpsVgHPmDrPoHsaZD4JS9X
kl8n5I3eP4JPIRaQzcfXqpr/KIarpfeAtP2ONwK4d5fS5mC+UoNq7CF2c4uo0MJQ
7yGxDKlYD77q72AveCr9r/xGV4HwXFcgJ5sKgYFClIUpQyGfL57gXG/DAoGATtgU
ZBbHGM0v/u7Ftvy031lqGQA22YTZx3YzDSlgsW7WGryXEqsMXuNlw1V7HmluGrI4
XXqMVgNEwRCf67F92gbPhXBARkwK2yAUBr8HhgIB7R8hG8KdybVeDRIdpy5dr1lY
4iL2reGVgd+oQkO30VzlCuhc9Rypv9esmuri6b0CgYEAnts5srGMWKsT+yyMRuyd
knTG8XP5pEbxVCbdV2b6t5BlqaWWdWX6n+uZPlOTXJfcLVe5n7LMpWg4FVTnfuje
afEvdqCMi8LXMu7558emcDGHDCvXt9OBO/aSsjEPAWtBT+g4bqHTSSdLaRhYqyj4
xib2bRSsBtnKKKFsk4Rr09g=
-----END PRIVATE KEY-----
"#;

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
