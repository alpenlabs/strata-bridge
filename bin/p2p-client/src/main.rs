//! The p2p-client binary main entry point.
#![expect(incomplete_features)] // the generic_const_exprs feature is incomplete
#![feature(generic_const_exprs)] // but necessary for using const generic bounds in p2p crate

use clap::Parser;
use cli::Cli;
use strata_common::logging::{self, LoggerConfig};
use tokio::runtime;
use tracing::{info, trace};

use crate::bootstrap::bootstrap;

mod bootstrap;
mod cli;
mod constants;

/// Main function for the p2p-client binary.
fn main() {
    logging::init(LoggerConfig::new("bridge-node".to_string()));

    let cli_args: Cli = Cli::parse();

    info!("starting node");
    trace!(action = "creating runtime", num_threads = %cli_args.num_threads, stack_size_per_thread_mb = %cli_args.stack_size);

    const NUM_BYTES_PER_MB: usize = 1024 * 1024;
    let runtime = runtime::Builder::new_multi_thread()
        .worker_threads(cli_args.num_threads)
        .thread_stack_size(cli_args.stack_size * NUM_BYTES_PER_MB)
        .enable_all()
        .build()
        .expect("must be able to create runtime");

    runtime.block_on(async {
        bootstrap(cli_args).await;
    });
}
