//! CLI for the alpen-bridge and dev-bridge.

mod constants;
mod handlers;

use anyhow::{Error, Result};
use clap::Parser;
use strata_bridge_common::logging::{self, LoggerConfig};

use crate::handlers::{bridge_in, bridge_out};

mod cli;

#[tokio::main]
async fn main() -> Result<(), Error> {
    logging::init(LoggerConfig::new("dev-cli".to_string()));

    let cli = cli::Cli::parse();
    match cli.command {
        cli::Commands::BridgeIn(args) => bridge_in::handle_bridge_in(args),
        cli::Commands::BridgeOut(args) => bridge_out::handle_bridge_out(args).await,
    }
}
