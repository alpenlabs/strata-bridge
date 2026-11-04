//! Command-line inputs for inspection, signing, and witness assembly.

use std::path::PathBuf;

use bitcoin::{hashes::sha256, Txid};
use clap::{Args, Parser, Subcommand};

/// Inspect or sign an authorization to spend a claim's payout connector.
#[derive(Debug, Parser)]
#[command(name = "admin-tool", version)]
pub(crate) struct Cli {
    /// Claim's N-of-N internal key and this tool's Bitcoin Core RPC connection (TOML).
    #[arg(long, global = true, default_value = "admin-tool.toml")]
    pub config: PathBuf,
    /// Existing bridge params containing the network, ordered admin keys, and threshold.
    #[arg(long, global = true, default_value = "params.toml")]
    pub params: PathBuf,
    /// Operation to perform.
    #[command(subcommand)]
    pub command: Command,
}

/// Available operations; neither funds nor broadcasts a transaction.
#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Validate the claim connector and show the signing details without a key.
    Inspect(ClaimArgs),
    /// Repeat validation and print one admin's signature as hex, including the sighash byte.
    Sign {
        /// Claim and public hashlock information.
        #[command(flatten)]
        claim: ClaimArgs,
        /// Existing admin private key file: 64 hex characters, with optional whitespace.
        #[arg(
            long,
            required_unless_present = "operator_seed_file",
            conflicts_with = "operator_seed_file"
        )]
        signer_file: Option<PathBuf>,
        /// Operator seed file: exactly 32 raw bytes; derives the operator's covenant key.
        #[arg(long)]
        operator_seed_file: Option<PathBuf>,
    },
    /// Verify shared admin signatures and print a transaction for external funding.
    Assemble {
        /// Claim and public hashlock information.
        #[command(flatten)]
        claim: ClaimArgs,
        /// 65-byte admin signature as hex, including the final 82; repeat for each signer.
        #[arg(long = "signature", required = true)]
        signatures: Vec<String>,
    },
}

impl Command {
    pub(crate) const fn claim(&self) -> &ClaimArgs {
        match &self {
            Command::Inspect(claim)
            | Command::Sign { claim, .. }
            | Command::Assemble { claim, .. } => claim,
        }
    }
}

/// Public inputs shared by all operations.
#[derive(Debug, Args)]
pub(crate) struct ClaimArgs {
    /// Claim whose payout output (index 1) is being authorized for spending.
    #[arg(long)]
    pub claim_txid: Txid,
    /// Public SHA-256 hash in the unstaking script; no secret preimage is needed.
    #[arg(long)]
    pub unstaking_hash: sha256::Hash,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_requires_exactly_one_key_source() {
        let claim = "11".repeat(32);
        let hash = "22".repeat(32);
        let args = [
            "admin-tool",
            "sign",
            "--claim-txid",
            &claim,
            "--unstaking-hash",
            &hash,
        ];

        assert!(Cli::try_parse_from(args).is_err());
        for flag in ["--signer-file", "--operator-seed-file"] {
            assert!(Cli::try_parse_from(args.into_iter().chain([flag, "key-file"])).is_ok());
        }
        assert!(Cli::try_parse_from(args.into_iter().chain([
            "--signer-file",
            "admin-key",
            "--operator-seed-file",
            "operator-seed",
        ]))
        .is_err());
    }
}
