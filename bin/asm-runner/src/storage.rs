//! Storage manager setup using SledDB from alpen

use std::{path::Path, sync::Arc};

use anyhow::Result;
use strata_db_store_sled::{AsmDBSled, GlobalMmrDb, SledDbConfig, open_sled_database};
use strata_storage::{AsmStateManager, GlobalMmrManager, MmrHandle, MmrId};
use threadpool::ThreadPool;

/// Create storage managers for ASM state and MMR
///
/// Returns a tuple of (AsmStateManager, MmrHandle) that can be used by the
/// WorkerContext and RPC server.
pub(crate) fn create_storage_managers(db_path: &Path) -> Result<(Arc<AsmStateManager>, MmrHandle)> {
    // Create thread pools for database operations
    let pool = ThreadPool::new(4);

    // Open sled databases
    let asm_sled_db = open_sled_database(db_path, "asm")?;
    let mmr_sled_db = open_sled_database(db_path, "mmr")?;

    // Create database instances with default config
    let config = SledDbConfig::new_with_constant_backoff(3, 100);
    let asm_db = Arc::new(AsmDBSled::new(asm_sled_db, config.clone())?);
    let mmr_db = Arc::new(GlobalMmrDb::new(mmr_sled_db, config)?);

    // Create managers
    let asm_manager = Arc::new(AsmStateManager::new(pool.clone(), asm_db));
    let mmr_manager = Arc::new(GlobalMmrManager::new(pool, mmr_db));

    // Get a handle for the ASM manifest MMR
    let mmr_handle = mmr_manager.get_handle(MmrId::Asm);

    Ok((asm_manager, mmr_handle))
}
