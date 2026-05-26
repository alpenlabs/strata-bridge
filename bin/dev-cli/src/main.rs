//! CLI for the alpen-bridge and dev-bridge.

mod handlers;

use anyhow::{Error, Result};
use clap::Parser;
use handlers::derive_keys;
use strata_bridge_common::logging;

use crate::handlers::{bridge_in, checkpoint, claim, contest, unstaking_intent};

mod cli;

#[tokio::main]
async fn main() -> Result<(), Error> {
    logging::init_from_env("dev-cli", "dev-cli");

    let cli = cli::Cli::parse();
    let result = match cli.command {
        cli::Commands::BridgeIn(args) => bridge_in::handle_bridge_in(args),
        cli::Commands::DeriveKeys(args) => derive_keys::handle_derive_keys(args),
        cli::Commands::CreateAndPublishMockCheckpoint(args) => {
            checkpoint::handle_create_and_publish_mock_checkpoint(args).await
        }
        cli::Commands::Contest(args) => contest::handle_contest(args).await,
        cli::Commands::Claim(args) => claim::handle_claim(args).await,
        cli::Commands::UnstakingIntent(args) => {
            unstaking_intent::handle_unstaking_intent(args).await
        }
    };

    logging::finalize();

    result
}
