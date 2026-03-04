//! CLI for the alpen-bridge and dev-bridge.

mod handlers;
mod params;

use anyhow::{Error, Result};
use clap::Parser;
use handlers::{challenge, derive_keys, disprove};
use strata_bridge_common::logging::{self, LoggerConfig};

use crate::handlers::{bridge_in, bridge_in_v2, bridge_out};

mod cli;

#[tokio::main]
async fn main() -> Result<(), Error> {
    logging::init(LoggerConfig::new("dev-cli".to_string()));

    let cli = cli::Cli::parse();
    match cli.command {
        cli::Commands::BridgeIn(args) => bridge_in::handle_bridge_in(args),
        cli::Commands::BridgeInV2(args) => bridge_in_v2::handle_bridge_in_v2(args),
        cli::Commands::BridgeOut(args) => bridge_out::handle_bridge_out(args).await,
        cli::Commands::Challenge(args) => challenge::handle_challenge(args).await,
        cli::Commands::Disprove(args) => disprove::handle_disprove(args).await,
        cli::Commands::DeriveKeys(args) => derive_keys::handle_derive_keys(args),
    }
}
