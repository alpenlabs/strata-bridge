use async_trait::async_trait;
use bitcoin::{Transaction, Txid};
use strata_bridge_primitives::duties::BridgeDutyStatus;

use crate::errors::DbResult;

#[async_trait]
pub trait DutyTrackerDb {
    async fn get_last_fetched_duty_index(&self) -> DbResult<u64>;

    async fn set_last_fetched_duty_index(&self, duty_index: u64) -> DbResult<()>;

    async fn fetch_duty_status(&self, duty_id: Txid) -> DbResult<Option<BridgeDutyStatus>>;

    async fn update_duty_status(&self, duty_id: Txid, status: BridgeDutyStatus) -> DbResult<()>;
}

#[async_trait]
pub trait BitcoinBlockTrackerDb {
    async fn get_last_scanned_block_height(&self) -> DbResult<u64>;

    async fn set_last_scanned_block_height(&self, block_height: u64) -> DbResult<()>;

    async fn get_relevant_tx(&self, txid: Txid) -> DbResult<Option<Transaction>>;

    async fn add_relevant_tx(&self, tx: Transaction) -> DbResult<()>;
}
