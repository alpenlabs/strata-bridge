use async_trait::async_trait;
use bitcoin::{PublicKey, Transaction, Txid};
use strata_bridge_primitives::duties::{
    BridgeDuties, BridgeDutyStatus, ClaimStatus, DepositRequestStatus, DepositStatus,
    WithdrawalStatus,
};

use crate::errors::DbResult;

#[async_trait]
pub trait DutyTrackerDb {
    async fn get_last_fetched_duty_index(&self) -> DbResult<u64>;

    async fn set_last_fetched_duty_index(&self, duty_index: u64) -> DbResult<()>;

    async fn fetch_duty_status(&self, duty_id: Txid) -> DbResult<Option<BridgeDutyStatus>>;

    async fn update_duty_status(&self, duty_id: Txid, status: BridgeDutyStatus) -> DbResult<()>;

    async fn get_all_duties(&self) -> DbResult<BridgeDuties>;

    async fn get_duties_by_operator_pk(&self, operator_pk: PublicKey) -> DbResult<BridgeDuties>;

    async fn get_all_claims(&self) -> DbResult<Vec<Txid>>;

    async fn get_claim_by_txid(&self, txid: Txid) -> DbResult<Option<ClaimStatus>>;

    async fn get_all_deposits(&self) -> DbResult<Vec<Txid>>;

    async fn get_deposit_by_txid(&self, txid: Txid) -> DbResult<Option<DepositStatus>>;

    async fn get_all_deposit_requests(&self) -> DbResult<Vec<Txid>>;

    async fn get_deposit_request_by_txid(
        &self,
        txid: Txid,
    ) -> DbResult<Option<DepositRequestStatus>>;

    async fn get_all_withdrawals(&self) -> DbResult<Vec<Txid>>;

    async fn get_withdrawal_by_txid(&self, txid: Txid) -> DbResult<Option<WithdrawalStatus>>;
}

#[async_trait]
pub trait BitcoinBlockTrackerDb {
    async fn get_last_scanned_block_height(&self) -> DbResult<u64>;

    async fn set_last_scanned_block_height(&self, block_height: u64) -> DbResult<()>;

    async fn get_relevant_tx(&self, txid: Txid) -> DbResult<Option<Transaction>>;

    async fn add_relevant_tx(&self, tx: Transaction) -> DbResult<()>;
}
