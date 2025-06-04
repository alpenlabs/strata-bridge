//! The Alpen Bridge is a bridge node for the Alpen BitVM rollup.

use std::{fs, path::Path, thread::sleep};

use args::OperationMode;
use clap::Parser;
use config::Config;
use constants::{DEFAULT_THREAD_COUNT, DEFAULT_THREAD_STACK_SIZE, STARTUP_DELAY};
use mimalloc::MiMalloc;
use mode::{operator, verifier};
use params::Params;
use serde::de::DeserializeOwned;
use strata_bridge_common::{logging, logging::LoggerConfig};
use tracing::{debug, info};

mod args;
mod config;
mod mode;
mod params;
mod rpc_server;

mod constants;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() {
    logging::init(LoggerConfig::with_base_name("bridge-node"));

    info!(?STARTUP_DELAY, "waiting for bitcoind setup phase");
    sleep(constants::STARTUP_DELAY);

    let cli = args::Cli::parse();
    info!(mode = %cli.mode, "starting bridge node");

    let params = parse_toml::<Params>(cli.params);
    let config = parse_toml::<Config>(cli.config);

    match cli.mode {
        OperationMode::Operator => {
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

            runtime.block_on(async move {
                operator::bootstrap(params, config)
                    .await
                    .unwrap_or_else(|e| {
                        panic!("operator loop crashed: {:?}", e);
                    });
            });
        }
        OperationMode::Verifier => {
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
            runtime.block_on(async move {
                verifier::bootstrap(params, config)
                    .await
                    .unwrap_or_else(|e| {
                        panic!("verifier loop crashed: {:?}", e);
                    });
            });
        }
    }
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
