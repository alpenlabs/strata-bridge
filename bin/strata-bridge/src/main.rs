//! Bridge Operator client.
//!
//! Responsible for facilitating bridge-in and bridge-out operations by creating, storing and
//! publishing appropriate transactions. Can also perform challenger duties.

mod bootstrap;
mod cli;
mod constants;
mod rpc_server;
pub mod xpriv;

use bootstrap::bootstrap;
use clap::Parser;
use cli::Cli;
use strata_common::logging;
use tracing::{info, trace};

fn main() {
    logging::init();

    let cli_args: Cli = Cli::parse();

    info!("starting node");
    trace!(action = "creating runtime", num_threads = %cli_args.num_threads, stack_size_per_thread_mb = %cli_args.stack_size);

    const NUM_BYTES_PER_MB: usize = 1024 * 1024;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(cli_args.num_threads)
        .thread_stack_size(cli_args.stack_size * NUM_BYTES_PER_MB)
        .enable_all()
        .build()
        .expect("must be able to create runtime");

    runtime.block_on(async {
        bootstrap(cli_args).await;
    });
}
