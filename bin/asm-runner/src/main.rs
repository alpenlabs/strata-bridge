//! ASM Runner Binary
//!
//! Standalone binary that runs the ASM (Anchor State Machine) STF and exposes an RPC API
//! for querying ASM state.
mod block_driver;
mod config;
mod rpc_server;
mod storage;
mod worker_context;

use std::{path::PathBuf, sync::Arc, time::Duration};

use anyhow::Result;
use bitcoind_async_client::{Auth, Client};
use clap::Parser;
use strata_asm_worker::AsmWorkerBuilder;
use strata_bridge_common::logging::{self, LoggerConfig};
use strata_params::RollupParams;
use strata_tasks::{TaskExecutor, TaskManager};
use tokio::runtime::{Builder, Handle};
use tracing::info;

use crate::{
    block_driver::setup_btc_tracker, config::AsmRpcConfig, rpc_server::run_rpc_server,
    worker_context::AsmWorkerContext,
};

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

/// Connect to Bitcoin node
async fn connect_bitcoin(config: &config::BitcoinConfig) -> Result<Client> {
    let client = Client::new(
        config.rpc_url.clone(),
        Auth::UserPass(config.rpc_user.clone(), config.rpc_password.clone()),
        None, // timeout
        config.retry_count,
        config.retry_interval,
    )?;

    Ok(client)
}

async fn bootstrap(
    config: AsmRpcConfig,
    params: RollupParams,
    executor: TaskExecutor,
) -> Result<()> {
    // 1. Create storage managers (AsmStateManager + MmrHandle)
    let (asm_manager, mmr_handle) = storage::create_storage_managers(&config.database.path)?;

    // 2. Connect to Bitcoin node
    let bitcoin_client = Arc::new(connect_bitcoin(&config.bitcoin).await?);

    // 3. Create our simplified BridgeWorkerContext
    let runtime_handle = Handle::current();
    let worker_context = AsmWorkerContext::new(
        runtime_handle.clone(),
        bitcoin_client.clone(),
        asm_manager.clone(),
        mmr_handle,
    );

    // 4. Launch ASM worker
    let asm_worker = AsmWorkerBuilder::new()
        .with_context(worker_context)
        .with_params(Arc::new(params.clone()))
        .launch(&executor)?;

    // 5. Set up BtcTracker to drive ASM
    let start_height = match asm_worker.monitor().get_current().cur_block {
        Some(blk) => blk.height_u64(),
        None => params.genesis_l1_view.height_u64(),
    };
    let btc_tracker =
        Arc::new(setup_btc_tracker(&config, bitcoin_client.clone(), start_height).await?);
    let asm_worker = Arc::new(asm_worker);

    // 6. Spawn block driver as a critical task
    let btc_tracker_for_driver = btc_tracker.clone();
    let asm_worker_for_driver = asm_worker.clone();
    executor.spawn_critical_async(
        "block_driver",
        block_driver::drive_asm_from_btc_tracker(btc_tracker_for_driver, asm_worker_for_driver),
    );

    // 7. Spawn RPC server as a critical task with graceful shutdown
    let rpc_host = config.rpc.host.clone();
    let rpc_port = config.rpc.port;
    executor.spawn_critical_async_with_shutdown("rpc_server", move |shutdown_guard| {
        run_rpc_server(
            asm_manager,
            asm_worker,
            bitcoin_client,
            rpc_host,
            rpc_port,
            shutdown_guard,
        )
    });

    Ok(())
}
