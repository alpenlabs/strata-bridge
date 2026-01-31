//! The Alpen Bridge is a bridge node for the Alpen BitVM rollup.
#![allow(
    incomplete_features,
    reason = "`strata-p2p` needs `generic_const_exprs` which itself is an `incomplete_feature`"
)]
#![feature(generic_const_exprs)] //strata-p2p

use std::{fs, path::Path, sync::Arc, thread::sleep};

use args::OperationMode;
use clap::Parser;
use config::Config;
use constants::{DEFAULT_THREAD_COUNT, DEFAULT_THREAD_STACK_SIZE, STARTUP_DELAY};
use mode::{init_secret_service_client, operator, verifier};
use params::Params;
use serde::de::DeserializeOwned;
use strata_bridge_common::{logging, logging::LoggerConfig};
use strata_bridge_db2::fdb::client::{FdbClient, MustDrop};
use strata_tasks::TaskManager;
use tokio::runtime;
use tracing::{debug, info, trace};

mod args;
mod config;
mod mode;
mod params;
mod rpc_server;

mod constants;

/// The default glibc malloc was observed to be responsible for bad memory fragmentation during
/// deposits which led to out-of-memory issues. [`Jemalloc`] is a general purpose malloc(3)
/// implementation that emphasizes fragmentation avoidance and scalable concurrency support.
/// It reduces the fragmentation so avoids overutilizing system memory
#[cfg(not(target_env = "msvc"))]
use tikv_jemallocator::Jemalloc;

#[cfg(not(target_env = "msvc"))]
#[global_allocator]
static GLOBAL: Jemalloc = Jemalloc;

/// Configures Jemalloc to support memory profiling when the feature is enabled.
/// This allows us to build flamegraphs for memory usage.
/// - `prof:true`: enables profiling for memory allocations
/// - `prof_active:true`: activates the profiling that was enabled by prev option
/// - `lg_prof_sample:19`: sampling interval of every 1 in 2^19 (~512kib) allocations
#[cfg(feature = "memory_profiling")]
#[expect(non_upper_case_globals)]
#[export_name = "malloc_conf"]
pub static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

fn main() {
    logging::init(LoggerConfig::with_base_name("bridge-node"));

    debug!(?STARTUP_DELAY, "waiting for bitcoind setup phase");
    sleep(constants::STARTUP_DELAY);

    let cli = args::Cli::parse();
    info!(mode = %cli.mode, "starting bridge node");

    let params = parse_toml::<Params>(cli.params);
    let config = parse_toml::<Config>(cli.config);
    let shutdown_timeout = config.shutdown_timeout;

    let runtime = runtime::Builder::new_multi_thread()
        .worker_threads(config.num_threads.unwrap_or(DEFAULT_THREAD_COUNT).into())
        .thread_stack_size(
            config
                .thread_stack_size
                .unwrap_or(DEFAULT_THREAD_STACK_SIZE),
        )
        .enable_all()
        .build()
        .expect("must be able to create runtime");

    // Initialize Secret Service client
    debug!("initializing secret service client");
    let s2_client = runtime.block_on(init_secret_service_client(&config.secret_service_client));

    // Initialize FDB client - must happen once per process, before spawning tasks.
    // The MustDrop guard stops the FDB network thread when dropped, so it must
    // stay in main() scope until after all tasks complete.
    // The root directory name is configured via config.fdb.root_directory (defaults to
    // "strata-bridge-v1").
    info!(root_directory = %config.fdb.root_directory, "initializing FoundationDB client");
    let (fdb_client, _fdb_guard): (FdbClient, MustDrop) = runtime
        .block_on(FdbClient::setup(config.fdb.clone()))
        .expect("should initialize FDB client");
    let fdb_client = Arc::new(fdb_client);
    debug!("FoundationDB client initialized");

    let task_manager = TaskManager::new(runtime.handle().clone());
    task_manager.start_signal_listeners();

    let executor = task_manager.create_executor();

    match cli.mode {
        OperationMode::Operator => {
            let fdb = fdb_client.clone();
            executor
                .clone()
                .spawn_critical_async("operator", async move {
                    #[cfg(feature = "memory_profiling")]
                    memory_pprof::setup_memory_profiling(3_000);
                    operator::bootstrap(params, config, s2_client, fdb, executor.clone()).await
                });
        }
        OperationMode::Verifier => {
            executor
                .clone()
                .spawn_critical_async("verifier", async move {
                    #[cfg(feature = "memory_profiling")]
                    memory_pprof::setup_memory_profiling(3_000);
                    verifier::bootstrap(params, config, executor.clone()).await
                });
        }
    }

    if let Err(e) = task_manager.monitor(Some(shutdown_timeout)) {
        panic!("bridge node crashed: {e:?}");
    }

    info!("bridge node shutdown complete");
}

/// Reads and parses a TOML file from the given path into the given type `T`.
///
/// # Panics
///
/// 1. If the file is not readable.
/// 2. If the contents of the file cannot be deserialized into the given type `T`.
fn parse_toml<T>(path: impl AsRef<Path>) -> T
where
    T: std::fmt::Debug + DeserializeOwned,
{
    fs::read_to_string(path)
        .map(|p| {
            trace!(?p, "read file");

            let parsed = toml::from_str::<T>(&p).unwrap_or_else(|e| {
                panic!("failed to parse TOML file: {e:?}");
            });
            debug!(?parsed, "parsed TOML file");

            parsed
        })
        .unwrap_or_else(|_| {
            panic!("failed to read TOML file");
        })
}
