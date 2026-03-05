//! Shared test utilities for FDB-backed trait implementations.

use std::sync::OnceLock;

use super::{
    cfg::Config,
    client::{FdbClient, MustDrop},
};

static TEST_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static FDB_BOOT: OnceLock<MustDrop> = OnceLock::new();
static SHARED_CLIENT: OnceLock<FdbClient> = OnceLock::new();

fn get_runtime() -> &'static tokio::runtime::Runtime {
    TEST_RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    })
}

/// Runs a future to completion, handling the case where we're already inside a runtime.
pub(crate) fn block_on<F: std::future::Future>(f: F) -> F::Output {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(f))
    } else {
        get_runtime().block_on(f)
    }
}

/// Boots the FDB network exactly once per process. Subsequent calls are no-ops.
fn boot_fdb() {
    FDB_BOOT.get_or_init(|| {
        block_on(async {
            let fdb_config = Config::default();
            // The first setup() call boots the FDB network. We discard the
            // client but keep the MustDrop guard alive for the process lifetime.
            let (_client, guard) = FdbClient::setup(fdb_config).await.unwrap();
            guard
        })
    });
}

/// Returns a shared [`FdbClient`] for tests that don't need isolation.
///
/// The client lives for the process lifetime and uses a single random
/// namespace.  Suitable for roundtrip tests that store/get by unique keys.
pub(crate) fn get_client() -> &'static FdbClient {
    boot_fdb();
    SHARED_CLIENT.get_or_init(|| {
        block_on(async {
            let fdb_config = Config::default();
            FdbClient::new_client_in_namespace(&fdb_config)
                .await
                .unwrap()
        })
    })
}

/// Creates a new [`FdbClient`] with a unique random namespace.
///
/// Each call returns a fully isolated client (different FDB directory),
/// so tests don't interfere with each other even when run in parallel
/// or across multiple proptest iterations.
pub(crate) fn new_test_client() -> FdbClient {
    boot_fdb();
    block_on(async {
        let fdb_config = Config::default();
        FdbClient::new_client_in_namespace(&fdb_config)
            .await
            .unwrap()
    })
}
