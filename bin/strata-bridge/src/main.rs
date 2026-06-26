//! Strata Bridge is a bridge node for the Strata protocol.
use std::{any::type_name, fs, path::Path, sync::Arc};

use args::OperationMode;
use clap::Parser;
use config::Config;
use constants::{DEFAULT_THREAD_COUNT, DEFAULT_THREAD_STACK_SIZE};
use mode::{operator, watchtower};
use serde::de::DeserializeOwned;
use strata_bridge_common::params::Params;
use strata_bridge_db::fdb::client::{FdbClient, MustDrop};
use strata_tasks::TaskManager;
use tokio::runtime;
use tracing::{debug, error, info, trace};

mod args;
mod config;
mod constants;
mod health;
mod mode;
mod observability;

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
#[unsafe(export_name = "malloc_conf")]
pub static malloc_conf: &[u8] = b"prof:true,prof_active:true,lg_prof_sample:19\0";

fn main() {
    let cli = args::Cli::parse();
    let mode_label = cli.mode.to_string();

    let config = parse_toml::<Config>(&cli.config);
    let params = parse_toml::<Params>(&cli.params);
    let network_label = params.network.to_string();
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

    let runtime_handle = runtime.handle().clone();
    {
        let _runtime_guard = runtime_handle.enter();
        observability::init(&config, &mode_label, &network_label, &runtime_handle);
    }

    info!(mode = %mode_label, network = %network_label, "starting bridge node");
    let health_registry = health::HealthRegistry::new();
    health_registry.mark_ok(health::COMPONENT_PROCESS, "process_started");

    // Initialize FDB client
    // Must happen once per process, before spawning tasks.
    // The MustDrop guard stops the FDB network thread when dropped, so it must
    // stay in main() scope until after all tasks complete.
    // The root directory name is configured via config.fdb.root_directory (defaults to
    // "strata-bridge-v1").
    info!(root_directory = %config.db.root_directory, "initializing FoundationDB client");
    let (fdb_client, _fdb_guard): (FdbClient, MustDrop) = runtime
        .block_on(FdbClient::setup(config.db.clone()))
        .expect("should initialize FDB client");
    let fdb_client = Arc::new(fdb_client);
    debug!("FoundationDB client initialized");
    health_registry.mark_ok(health::COMPONENT_FDB, "client_initialized");

    let task_manager = TaskManager::new(runtime_handle);
    task_manager.start_signal_listeners();

    let executor = task_manager.create_executor();

    match cli.mode {
        OperationMode::Operator => {
            let fdb = fdb_client.clone();
            let health_registry = health_registry.clone();
            executor
                .clone()
                .spawn_critical_async("operator", async move {
                    #[cfg(feature = "memory_profiling")]
                    memory_pprof::setup_memory_profiling(3_000);
                    operator::bootstrap(params, config, fdb, executor.clone(), health_registry)
                        .await
                });
        }
        OperationMode::Watchtower => {
            executor
                .clone()
                .spawn_critical_async("watchtower", async move {
                    #[cfg(feature = "memory_profiling")]
                    memory_pprof::setup_memory_profiling(3_000);
                    watchtower::bootstrap(params, config, executor.clone()).await
                });
        }
    }

    if let Err(e) = task_manager.monitor(Some(shutdown_timeout)) {
        error!(err = ?e, "bridge node crashed");
        observability::finalize();
        panic!("bridge node crashed: {e:?}");
    }

    info!("bridge node shutdown complete");
    observability::finalize();
}

/// Reads and parses a TOML file from the given path into the given type `T`.
///
/// # Panics
///
/// 1. If the file is not readable.
/// 2. If the contents of the file cannot be deserialized into the given type `T`.
fn parse_toml<T>(path: impl AsRef<Path>) -> T
where
    T: DeserializeOwned,
{
    let path = path.as_ref();
    let contents = fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read TOML file {}: {e}", path.display()));
    trace!(path = %path.display(), "read TOML file");

    let parsed = toml::from_str::<T>(&contents)
        .unwrap_or_else(|e| panic!("failed to parse TOML file {}: {e}", path.display()));
    debug!(path = %path.display(), target_type = type_name::<T>(), "parsed TOML file");

    parsed
}
