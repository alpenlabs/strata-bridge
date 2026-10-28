//! Command-line inputs for inspection and signing.

use std::path::PathBuf;

use bitcoin::{hashes::sha256, Txid};
use clap::{Args, Parser, Subcommand};

/// Inspect or sign an authorization to spend a claim's payout connector.
#[derive(Debug, Parser)]
#[command(name = "admin-tool", version)]
pub(crate) struct Cli {
    /// Shared admin settings and Bitcoin Core RPC connection (TOML).
    #[arg(long, global = true, default_value = "admin-tool.toml")]
    pub config: PathBuf,
    /// Operation to perform.
    #[command(subcommand)]
    pub command: Command,
}

/// Available operations; neither funds nor broadcasts a transaction.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Validate the claim connector and show the signing details without a key.
    Inspect(ClaimArgs),
    /// Repeat validation and print one admin's signature as JSON.
    Sign {
        /// Claim and public hashlock information.
        #[command(flatten)]
        claim: ClaimArgs,
        /// Existing admin private key file: 64 hex characters, with optional whitespace.
        #[arg(long)]
        signer_file: PathBuf,
    },
}

/// Public inputs shared by both operations.
#[derive(Debug, Args)]
pub(crate) struct ClaimArgs {
    /// Claim whose payout output (index 1) is being authorized for spending.
    #[arg(long)]
    pub claim_txid: Txid,
    /// Public SHA-256 hash in the unstaking script; no secret preimage is needed.
    #[arg(long)]
    pub unstaking_hash: sha256::Hash,
}
