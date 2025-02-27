//! The p2p-client binary main entry point.

use clap::Parser;
use cli::Cli;
use message_handler::MessageHandler;
use strata_common::logging::{self, LoggerConfig};
use tokio::runtime;
use tracing::{info, trace};

use crate::bootstrap::bootstrap;

mod bootstrap;
mod cli;
mod constants;
mod message_handler;
#[cfg(test)]
mod test;

/// Main function for the p2p-client binary.
fn main() -> anyhow::Result<()> {
    logging::init(LoggerConfig::new("p2p-node".to_string()));

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
        let (handle, cancel) = bootstrap(cli_args.clone())
            .await
            .expect("Failed to bootstrap");

        // Generate a keypair for signing messages
        let keypair = cli_args
            .extract_config()
            .expect("must be able to extract config")
            .keypair;

        // Create a message handler
        let mut handler = MessageHandler::new(handle, keypair);

        // Listen for events
        handler.listen_for_events().await;

        // Wait for cancellation
        cancel.cancelled().await;
    });

    Ok(())
}
