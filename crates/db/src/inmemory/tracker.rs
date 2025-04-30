use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bitcoin::{PublicKey, Transaction, Txid};
use strata_bridge_primitives::duties::{
    BridgeDuties, BridgeDuty, BridgeDutyStatus, ClaimStatus, DepositRequestStatus, DepositStatus,
    WithdrawalStatus,
};
use tokio::sync::RwLock;

use crate::{
    errors::DbResult,
    tracker::{BitcoinBlockTrackerDb, DutyTrackerDb},
};

/// In-memory implementation of the duty tracker database.
#[derive(Debug, Clone, Default)]
pub struct DutyTrackerInMemory {
    /// Last fetched duty index.
    last_fetched_duty_index: Arc<RwLock<u64>>,

    /// Status of each duty.
    duty_status: Arc<RwLock<HashMap<Txid, BridgeDutyStatus>>>,

    /// Bridge duties.
    duties: Arc<RwLock<HashMap<PublicKey, BridgeDuty>>>,
}

#[async_trait]
impl DutyTrackerDb for DutyTrackerInMemory {
    async fn get_last_fetched_duty_index(&self) -> DbResult<u64> {
        Ok(*self.last_fetched_duty_index.read().await)
    }

    async fn set_last_fetched_duty_index(&self, duty_index: u64) -> DbResult<()> {
        let mut new_duty_index = self.last_fetched_duty_index.write().await;

        *new_duty_index = duty_index;

        Ok(())
    }

    async fn fetch_duty_status(&self, duty_id: Txid) -> DbResult<Option<BridgeDutyStatus>> {
        Ok(self.duty_status.read().await.get(&duty_id).cloned())
    }

    async fn update_duty_status(&self, duty_id: Txid, status: BridgeDutyStatus) -> DbResult<()> {
        let mut duty_status = self.duty_status.write().await;

        if let Some(duty_status) = duty_status.get_mut(&duty_id) {
            *duty_status = status;
        } else {
            duty_status.insert(duty_id, status);
        }

        Ok(())
    }

    async fn get_all_duties(&self) -> DbResult<BridgeDuties> {
        let duties = self.duties.read().await;
        let duties_vec: Vec<BridgeDuty> = duties.values().cloned().collect();
        let len = duties_vec.len() as u64;

        Ok(BridgeDuties {
            duties: duties_vec,
            start_index: 0,
            stop_index: len,
        })
    }

    async fn get_duties_by_operator_pk(&self, operator_pk: PublicKey) -> DbResult<BridgeDuties> {
        let duties = self.duties.read().await;
        let duties_vec: Vec<BridgeDuty> = duties
            .keys()
            .filter(|pk| *pk == &operator_pk)
            .map(|pk| duties[pk].clone())
            .collect();
        let len = duties_vec.len() as u64;

        Ok(BridgeDuties {
            duties: duties_vec,
            start_index: 0,
            stop_index: len,
        })
    }

    async fn get_all_claims(&self) -> DbResult<Vec<Txid>> {
        unimplemented!("@rajil")
    }

    async fn get_claim_by_txid(&self, txid: Txid) -> DbResult<Option<ClaimStatus>> {
        let _ = txid;
        unimplemented!("@rajil")
    }

    async fn get_all_deposits(&self) -> DbResult<Vec<Txid>> {
        unimplemented!("@rajil")
    }

    async fn get_deposit_by_txid(&self, txid: Txid) -> DbResult<Option<DepositStatus>> {
        let _ = txid;
        unimplemented!("@rajil")
    }

    async fn get_all_deposit_requests(&self) -> DbResult<Vec<Txid>> {
        unimplemented!("@rajil")
    }

    async fn get_deposit_request_by_txid(
        &self,
        txid: Txid,
    ) -> DbResult<Option<DepositRequestStatus>> {
        let _ = txid;
        unimplemented!("@rajil")
    }

    async fn get_all_withdrawals(&self) -> DbResult<Vec<Txid>> {
        unimplemented!("@rajil")
    }

    async fn get_withdrawal_by_txid(&self, txid: Txid) -> DbResult<Option<WithdrawalStatus>> {
        let _ = txid;
        unimplemented!("@rajil")
    }
}

#[derive(Debug, Clone, Default)]
pub struct BitcoinBlockTrackerInMemory {
    last_scanned_block_height: Arc<RwLock<u64>>,

    relevant_txs: Arc<RwLock<HashMap<Txid, Transaction>>>,
}

#[async_trait]
impl BitcoinBlockTrackerDb for BitcoinBlockTrackerInMemory {
    async fn get_last_scanned_block_height(&self) -> DbResult<u64> {
        Ok(*self.last_scanned_block_height.read().await)
    }

    async fn set_last_scanned_block_height(&self, block_height: u64) -> DbResult<()> {
        let mut height = self.last_scanned_block_height.write().await;

        *height = block_height;

        Ok(())
    }

    async fn get_relevant_tx(&self, txid: Txid) -> DbResult<Option<Transaction>> {
        Ok(self.relevant_txs.read().await.get(&txid).cloned())
    }

    async fn add_relevant_tx(&self, tx: Transaction) -> DbResult<()> {
        let txid = tx.compute_txid();

        self.relevant_txs.write().await.insert(txid, tx);

        Ok(())
    }
}
