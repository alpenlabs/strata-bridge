use std::sync::Arc;

use anyhow::Result;
use bitcoind_async_client::{Auth, Client};
use strata_asm_worker::AsmWorkerBuilder;
use strata_params::RollupParams;
use strata_tasks::TaskExecutor;
use tokio::runtime::Handle;

use crate::{
    block_driver::{drive_asm_from_btc_tracker, setup_btc_tracker},
    config::{AsmRpcConfig, BitcoinConfig},
    rpc_server::run_rpc_server,
    storage::create_storage_managers,
    worker_context::AsmWorkerContext,
};
pub(crate) async fn bootstrap(
    config: AsmRpcConfig,
    params: RollupParams,
    executor: TaskExecutor,
) -> Result<()> {
    // 1. Create storage managers (AsmStateManager + MmrHandle)
    let (asm_manager, mmr_handle) = create_storage_managers(&config.database)?;

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
        drive_asm_from_btc_tracker(btc_tracker_for_driver, asm_worker_for_driver),
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

/// Connect to Bitcoin node
async fn connect_bitcoin(config: &BitcoinConfig) -> Result<Client> {
    let client = Client::new(
        config.rpc_url.clone(),
        Auth::UserPass(config.rpc_user.clone(), config.rpc_password.clone()),
        None, // timeout
        config.retry_count,
        config.retry_interval.map(|d| d.as_millis() as u64),
    )?;

    Ok(client)
}
