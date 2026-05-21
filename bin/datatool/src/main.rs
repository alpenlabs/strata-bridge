//! `datatool` — command-line tooling for the bridge prover.
//!
//! A home for proof-related helpers, meant to grow with future proving work.

use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use strata_bridge_proof::sp1_groth16_predicate_string;

/// Bridge prover tooling.
#[derive(Parser)]
#[command(name = "datatool", about = "Bridge prover tooling")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Print the `Sp1Groth16:<hex>` predicate pinning an SP1 guest ELF's verifying key.
    Sp1Predicate {
        /// Path to the SP1 guest ELF.
        elf: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Sp1Predicate { elf } => {
            let bytes = std::fs::read(&elf)
                .with_context(|| format!("failed to read ELF at {}", elf.display()))?;
            let predicate = sp1_groth16_predicate_string(&bytes)
                .context("failed to derive Sp1Groth16 predicate")?;
            println!("{predicate}");
            Ok(())
        }
    }
}
