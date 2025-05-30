//! Database traits for the duty tracker.

use async_trait::async_trait;
use bitcoin::{PublicKey, Transaction, Txid};
use strata_bridge_primitives::duties::{
    BridgeDuty, BridgeDutyStatus, ClaimStatus, DepositRequestStatus, DepositStatus,
    WithdrawalStatus,
};

use crate::errors::DbResult;

/// Duty tracker database.
#[async_trait]
pub trait DutyTrackerDb {
    /// Returns the last fetched duty index.
    async fn get_last_fetched_duty_index(&self) -> DbResult<u64>;

    /// Sets the last fetched duty index.
    async fn set_last_fetched_duty_index(&self, duty_index: u64) -> DbResult<()>;

    /// Fetches the duty status.
    async fn fetch_duty_status(&self, duty_id: Txid) -> DbResult<Option<BridgeDutyStatus>>;

    /// Updates the duty status.
    async fn update_duty_status(&self, duty_id: Txid, status: BridgeDutyStatus) -> DbResult<()>;

    /// Returns all duties.
    async fn get_all_duties(&self) -> DbResult<Vec<BridgeDuty>>;

    /// Returns duties by operator public key.
    async fn get_duties_by_operator_pk(&self, operator_pk: PublicKey) -> DbResult<Vec<BridgeDuty>>;

    /// Returns all claims.
    async fn get_all_claims(&self) -> DbResult<Vec<Txid>>;

    /// Returns a claim by transaction ID.
    async fn get_claim_by_txid(&self, txid: Txid) -> DbResult<Option<ClaimStatus>>;

    /// Returns all deposits.
    async fn get_all_deposits(&self) -> DbResult<Vec<Txid>>;

    /// Returns a deposit by transaction ID.
    async fn get_deposit_by_txid(&self, txid: Txid) -> DbResult<Option<DepositStatus>>;

    /// Returns all deposit requests.
    async fn get_all_deposit_requests(&self) -> DbResult<Vec<Txid>>;

    /// Returns a deposit request by transaction ID.
    async fn get_deposit_request_by_txid(
        &self,
        txid: Txid,
    ) -> DbResult<Option<DepositRequestStatus>>;

    /// Returns all withdrawals.
    async fn get_all_withdrawals(&self) -> DbResult<Vec<Txid>>;

    /// Returns a withdrawal by transaction ID.
    async fn get_withdrawal_by_txid(&self, txid: Txid) -> DbResult<Option<WithdrawalStatus>>;
}

/// Bitcoin block tracker database.
#[async_trait]
pub trait BitcoinBlockTrackerDb {
    /// Returns the last scanned block height.
    async fn get_last_scanned_block_height(&self) -> DbResult<u64>;

    /// Sets the last scanned block height.
    async fn set_last_scanned_block_height(&self, block_height: u64) -> DbResult<()>;

    /// Returns a relevant transaction by transaction ID.
    async fn get_relevant_tx(&self, txid: Txid) -> DbResult<Option<Transaction>>;

    /// Adds a relevant transaction.
    async fn add_relevant_tx(&self, tx: Transaction) -> DbResult<()>;
}
