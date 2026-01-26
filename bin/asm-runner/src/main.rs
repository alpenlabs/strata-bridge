//! ASM Runner Binary
//!
//! Standalone binary that runs the ASM (Anchor State Machine) STF and exposes an RPC API
//! for querying ASM state.
mod config;

use std::path::PathBuf;

use anyhow::Result;
use clap::Parser;
use strata_bridge_common::logging::{self, LoggerConfig};
use strata_params::RollupParams;
use tracing::info;

use crate::config::AsmRpcConfig;

/// ASM Runner - Run the ASM STF and expose RPC API
#[derive(Parser, Debug)]
#[command(name = "asm-runner")]
#[command(about = "ASM runner for executing ASM STF", long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Path to rollup params JSON file
    #[arg(short, long)]
    params: PathBuf,
}

fn main() {
    // 1. Initialize logging
    logging::init(LoggerConfig::with_base_name("asm-runner"));

    // 2. Parse CLI args
    let cli = Cli::parse();

    // 3. Load configuration
    let config = load_config(&cli.config).expect("Failed to load config");

    // 4. Load rollup params (for ASM spec)
    let params = load_params(&cli.params).expect("Failed to load params");

    info!(
        "Starting ASM RPC server with config: {:?}, params: {:?}",
        config, params
    );
}

/// Load rollup parameters
fn load_params(params_path: &PathBuf) -> Result<RollupParams> {
    let contents = std::fs::read_to_string(params_path)?;
    let params: RollupParams = serde_json::from_str(&contents)?;
    Ok(params)
}

/// Load configuration from file
fn load_config(path: &PathBuf) -> Result<AsmRpcConfig> {
    let contents = std::fs::read_to_string(path)?;
    let config: AsmRpcConfig = toml::from_str(&contents)?;
    Ok(config)
}
