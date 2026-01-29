//! Storage manager setup using SledDB from alpen

use std::{sync::Arc, time::Duration};

use anyhow::Result;
use strata_db_store_sled::{AsmDBSled, GlobalMmrDb, SledDbConfig, open_sled_database};
use strata_storage::{AsmStateManager, GlobalMmrManager, MmrHandle, MmrId};
use threadpool::ThreadPool;

use crate::config::DatabaseConfig;

/// Default number of threads for database operations.
const DEFAULT_NUM_THREADS: usize = 4;

/// Default number of retries for failed database operations.
const DEFAULT_RETRY_COUNT: u16 = 4;

/// Default delay between retries for failed database operations.
const DEFAULT_DELAY: Duration = Duration::from_millis(150);

/// Sled database name for MMR data.
const MMR_DB_NAME: &str = "mmr";
/// Sled database name for ASM state data.
const ASM_DB_NAME: &str = "asm";

/// Create storage managers for ASM state and MMR
///
/// Returns a tuple of (AsmStateManager, MmrHandle) that can be used by the
/// WorkerContext and RPC server.
pub(crate) fn create_storage_managers(
    config: &DatabaseConfig,
) -> Result<(Arc<AsmStateManager>, MmrHandle)> {
    // Create thread pools for database operations
    let pool = ThreadPool::new(config.num_threads.unwrap_or(DEFAULT_NUM_THREADS));

    // Open sled databases
    let asm_sled_db = open_sled_database(&config.path, ASM_DB_NAME)?;
    let mmr_sled_db = open_sled_database(&config.path, MMR_DB_NAME)?;

    // Create database instances with default config
    let config = SledDbConfig::new_with_constant_backoff(
        config.retry_count.unwrap_or(DEFAULT_RETRY_COUNT),
        config.delay.unwrap_or(DEFAULT_DELAY).as_millis() as u64,
    );
    let asm_db = Arc::new(AsmDBSled::new(asm_sled_db, config.clone())?);
    let mmr_db = Arc::new(GlobalMmrDb::new(mmr_sled_db, config)?);

    // Create managers
    let asm_manager = Arc::new(AsmStateManager::new(pool.clone(), asm_db));
    let mmr_manager = Arc::new(GlobalMmrManager::new(pool, mmr_db));

    // Get a handle for the ASM manifest MMR
    let mmr_handle = mmr_manager.get_handle(MmrId::Asm);

    Ok((asm_manager, mmr_handle))
}
