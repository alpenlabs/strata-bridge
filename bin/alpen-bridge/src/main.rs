//! The Alpen Bridge is a bridge node for the Alpen BitVM rollup.

#[cfg(not(unix))]
use std::future::pending;
use std::{fmt, fs, path::Path, process, thread::sleep};

use args::OperationMode;
use clap::Parser;
use config::Config;
use constants::{DEFAULT_THREAD_COUNT, DEFAULT_THREAD_STACK_SIZE, STARTUP_DELAY};
use mode::{operator, verifier};
use params::Params;
use serde::de::DeserializeOwned;
use strata_bridge_common::{logging, logging::LoggerConfig};
#[cfg(unix)]
use tokio::signal::unix::{signal, SignalKind};
use tokio::{select, signal::ctrl_c};
use tracing::{debug, error, info};

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

    info!(?STARTUP_DELAY, "waiting for bitcoind setup phase");
    sleep(constants::STARTUP_DELAY);

    let cli = args::Cli::parse();
    info!(mode = %cli.mode, "starting bridge node");

    let params = parse_toml::<Params>(cli.params);
    let config = parse_toml::<Config>(cli.config);

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(config.num_threads.unwrap_or(DEFAULT_THREAD_COUNT).into())
        .thread_stack_size(
            config
                .thread_stack_size
                .unwrap_or(DEFAULT_THREAD_STACK_SIZE),
        )
        .enable_all()
        .build()
        .expect("must be able to create runtime");

    let exit_code = runtime.block_on(async move {
        #[cfg(feature = "memory_profiling")]
        memory_pprof::setup_memory_profiling(3_000);

        let bootstrap_task = async {
            match cli.mode {
                OperationMode::Operator => operator::bootstrap(params, config).await,
                OperationMode::Verifier => verifier::bootstrap(params, config).await,
            }
        };

        select! {
            result = bootstrap_task => {
                match result {
                    Ok(()) => {
                        info!("bridge node completed successfully");
                        0
                    }
                    Err(e) => {
                        error!(?e, "bridge node failed");
                        1
                    }
                }
            }
            _ = ctrl_c() => {
                info!("received CTRL+C signal, initiating graceful shutdown");
                0
            }
            _ = setup_sigterm_handler() => {
                info!("received SIGTERM signal, initiating graceful shutdown");
                0
            }
        }
    });

    if exit_code != 0 {
        process::exit(exit_code);
    }
}

/// Sets up SIGTERM signal handler for Unix systems.
#[cfg(unix)]
async fn setup_sigterm_handler() {
    let mut sigterm = signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
    sigterm.recv().await;
}

/// No-op SIGTERM handler for non-Unix systems.
#[cfg(not(unix))]
async fn setup_sigterm_handler() {
    // On non-Unix systems, just wait indefinitely (this branch will never be taken due to
    // tokio::select!)
    pending::<()>().await;
}

/// Reads and parses a TOML file from the given path into the given type `T`.
///
/// # Panics
///
/// 1. If the file is not readable.
/// 2. If the contents of the file cannot be deserialized into the given type `T`.
fn parse_toml<T>(path: impl AsRef<Path>) -> T
where
    T: fmt::Debug + DeserializeOwned,
{
    fs::read_to_string(path)
        .map(|p| {
            debug!(?p, "read file");

            let parsed = toml::from_str::<T>(&p).unwrap_or_else(|e| {
                panic!("failed to parse TOML file: {:?}", e);
            });
            debug!(?parsed, "parsed TOML file");

            parsed
        })
        .unwrap_or_else(|_| {
            panic!("failed to read TOML file");
        })
}
