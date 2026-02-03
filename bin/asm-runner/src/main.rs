//! ASM Runner Binary
//!
//! Standalone binary that runs the ASM (Anchor State Machine) STF and exposes an RPC API
//! for querying ASM state.
mod block_driver;
mod bootstrap;
mod config;
mod rpc_server;
mod storage;
mod worker_context;

use std::{path::PathBuf, time::Duration};

use anyhow::Result;
use clap::Parser;
use strata_bridge_common::logging::{self, LoggerConfig};
use strata_params::RollupParams;
use strata_tasks::TaskManager;
use tokio::runtime::Builder;
use tracing::info;

use crate::{bootstrap::bootstrap, config::AsmRpcConfig};

/// ASM Runner - Run the ASM STF and expose RPC API
#[derive(Parser, Debug)]
#[command(name = "asm-runner")]
#[command(about = "ASM runner for executing ASM STF", long_about = None)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Path to rollup params JSON file
    #[arg(short, long, default_value = "params.json")]
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

    // 5. Create tokio runtime
    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to create tokio runtime");

    // 6. Create task manager and start signal listeners
    let task_manager = TaskManager::new(runtime.handle().clone());
    task_manager.start_signal_listeners();
    let executor = task_manager.create_executor();

    // 7. Spawn the main async initialization and server logic as a critical task
    let executor_clone = executor.clone();
    executor.spawn_critical_async("main_task", async move {
        bootstrap(config, params, executor_clone).await
    });

    // 8. Monitor all tasks and handle shutdown
    let shutdown_timeout = Duration::from_secs(30);
    if let Err(e) = task_manager.monitor(Some(shutdown_timeout)) {
        panic!("ASM RPC server crashed: {e:?}");
    }

    tracing::info!("ASM RPC server shutdown complete");
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
