//! Storage setup for the ASM runner.

use std::sync::Arc;

use anyhow::Result;
use asm_storage::{AsmStateDb, MmrDb};

use crate::config::DatabaseConfig;

/// Create storage backends for the ASM runner.
pub(crate) fn create_storage(config: &DatabaseConfig) -> Result<(Arc<AsmStateDb>, Arc<MmrDb>)> {
    let db = sled::open(&config.path)?;
    let state_db = Arc::new(AsmStateDb::open(&db)?);
    let mmr_db = Arc::new(MmrDb::open(&db)?);
    Ok((state_db, mmr_db))
}
