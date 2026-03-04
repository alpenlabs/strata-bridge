//! Shared test utilities for FDB-backed trait implementations.

use std::sync::OnceLock;

use secp256k1::rand::random;

use super::{
    cfg::Config,
    client::{FdbClient, MustDrop},
};

static TEST_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static FDB_CLIENT: OnceLock<(FdbClient, MustDrop)> = OnceLock::new();

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

pub(crate) fn get_client() -> &'static FdbClient {
    &FDB_CLIENT
        .get_or_init(|| {
            block_on(async {
                let random_suffix: u64 = random();
                let fdb_config = Config {
                    root_directory: format!("test-{random_suffix}"),
                    ..Default::default()
                };
                FdbClient::setup(fdb_config).await.unwrap()
            })
        })
        .0
}
