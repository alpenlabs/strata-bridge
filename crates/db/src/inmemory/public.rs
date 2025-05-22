//! In-memory database traits and implementations for the public.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bitcoin::{OutPoint, Txid};
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::{constants::NUM_ASSERT_DATA_TX, types::OperatorIdx, wots};
use strata_bridge_stake_chain::transactions::stake::StakeTxData;
use tokio::sync::RwLock;
use tracing::trace;

use crate::{errors::DbResult, public::PublicDb};

/// A map of transaction input to signature.
pub type TxInputToSignatureMap = HashMap<(Txid, u32), Signature>;

/// A map of operator index to transaction input to signature.
pub type OperatorIdxToTxInputSigMap = HashMap<OperatorIdx, TxInputToSignatureMap>;

/// In-memory database for the public.
// Assume that no node will update other nodes' data in this public db.
#[derive(Debug, Default, Clone)]
pub struct PublicDbInMemory {
    /// operator_id -> deposit_txid -> WotsPublicKeys
    wots_public_keys: Arc<RwLock<HashMap<OperatorIdx, HashMap<Txid, wots::PublicKeys>>>>,

    /// operator_id -> deposit_txid -> WotsSignatures
    wots_signatures: Arc<RwLock<HashMap<OperatorIdx, HashMap<Txid, wots::Signatures>>>>,

    /// signature cache per txid and input index per operator
    signatures: Arc<RwLock<OperatorIdxToTxInputSigMap>>,

    /// deposit_txid -> deposit_id
    deposits_table: Arc<RwLock<HashMap<Txid, u32>>>,

    /// operator_id -> deposit_id -> stake_txid
    stake_txid_table: Arc<RwLock<HashMap<OperatorIdx, HashMap<u32, Txid>>>>,

    /// operator_id -> pre stake txid
    pre_stake_table: Arc<RwLock<HashMap<OperatorIdx, OutPoint>>>,

    /// operator_id -> stake_id -> stake_data
    stake_data: Arc<RwLock<HashMap<OperatorIdx, HashMap<u32, StakeTxData>>>>,

    /// reverse mapping
    /// claim_txid -> (operator_index, deposit_txid)
    claim_txid_to_operator_index_and_deposit_txid: Arc<RwLock<HashMap<Txid, (OperatorIdx, Txid)>>>,

    /// pre_assert_txid -> (operator_index, deposit_txid)
    pre_assert_txid_to_operator_index_and_deposit_txid:
        Arc<RwLock<HashMap<Txid, (OperatorIdx, Txid)>>>,

    /// assert_data_txid -> (operator_index, deposit_txid)
    assert_data_txid_to_operator_index_and_deposit_txid:
        Arc<RwLock<HashMap<Txid, (OperatorIdx, Txid)>>>,

    /// post_assert_txid -> (operator_index, deposit_txid)
    post_assert_txid_to_operator_index_and_deposit_txid:
        Arc<RwLock<HashMap<Txid, (OperatorIdx, Txid)>>>,
}

#[async_trait]
impl PublicDb for PublicDbInMemory {
    async fn get_wots_public_keys(
        &self,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<Option<wots::PublicKeys>> {
        Ok(self
            .wots_public_keys
            .read()
            .await
            .get(&operator_idx)
            .and_then(|m| m.get(&deposit_txid))
            .cloned())
    }

    async fn get_wots_signatures(
        &self,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<Option<wots::Signatures>> {
        Ok(self
            .wots_signatures
            .read()
            .await
            .get(&operator_idx)
            .and_then(|m| m.get(&deposit_txid))
            .cloned())
    }

    async fn set_wots_public_keys(
        &self,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
        public_keys: &wots::PublicKeys,
    ) -> DbResult<()> {
        trace!(action = "trying to acquire wlock on wots public keys", %operator_idx, %deposit_txid);
        let mut map = self.wots_public_keys.write().await;
        trace!(event = "wlock acquired on wots public keys", %operator_idx, %deposit_txid);

        if let Some(op_keys) = map.get_mut(&operator_idx) {
            op_keys.insert(deposit_txid, public_keys.clone());
        } else {
            let mut keys = HashMap::new();
            keys.insert(deposit_txid, public_keys.clone());

            map.insert(operator_idx, keys);
        }

        Ok(())
    }

    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<Signature>> {
        Ok(self
            .signatures
            .read()
            .await
            .get(&operator_idx)
            .and_then(|m| m.get(&(txid, input_index)))
            .copied())
    }

    async fn set_wots_signatures(
        &self,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
        signatures: &wots::Signatures,
    ) -> DbResult<()> {
        trace!(action = "trying to acquire lock on wots signatures", %operator_idx, %deposit_txid);
        let mut map = self.wots_signatures.write().await;
        trace!(event = "wlock acquired on wots signatures", %operator_idx, %deposit_txid);

        if let Some(op_keys) = map.get_mut(&operator_idx) {
            op_keys.insert(deposit_txid, signatures.clone());
        } else {
            let mut sigs_map = HashMap::new();
            sigs_map.insert(deposit_txid, signatures.clone());

            map.insert(operator_idx, sigs_map);
        }

        Ok(())
    }

    async fn set_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) -> DbResult<()> {
        trace!(action = "trying to acquire wlock on schnorr signatures", %operator_idx, %txid);
        let mut signatures = self.signatures.write().await;
        trace!(event = "acquired wlock on schnorr signatures", %operator_idx, %txid);

        if let Some(txid_and_input_index_to_signature) = signatures.get_mut(&operator_idx) {
            txid_and_input_index_to_signature.insert((txid, input_index), signature);
        } else {
            let mut txid_and_input_index_to_signature = HashMap::new();
            txid_and_input_index_to_signature.insert((txid, input_index), signature);

            signatures.insert(operator_idx, txid_and_input_index_to_signature);
        }

        Ok(())
    }

    async fn add_deposit_txid(&self, deposit_txid: Txid) -> DbResult<()> {
        let mut deposits_table = self.deposits_table.write().await;
        let new_index = deposits_table.keys().count();
        deposits_table.insert(deposit_txid, new_index as u32);

        Ok(())
    }

    async fn get_deposit_id(&self, deposit_txid: Txid) -> DbResult<Option<u32>> {
        Ok(self.deposits_table.read().await.get(&deposit_txid).copied())
    }

    async fn add_stake_txid(&self, operator_idx: OperatorIdx, stake_txid: Txid) -> DbResult<()> {
        let mut stake_txid_table = self.stake_txid_table.write().await;
        // get number of stake ids for this operator
        let stake_id = stake_txid_table
            .get(&operator_idx)
            .map_or(0, |m| m.keys().count() as u32);

        if let Some(m) = stake_txid_table.get_mut(&operator_idx) {
            m.insert(stake_id, stake_txid);
        } else {
            let mut m = HashMap::new();
            m.insert(stake_id, stake_txid);

            stake_txid_table.insert(operator_idx, m);
        }

        Ok(())
    }

    async fn get_stake_txid(
        &self,
        operator_idx: OperatorIdx,
        stake_id: u32,
    ) -> DbResult<Option<Txid>> {
        Ok(self
            .stake_txid_table
            .read()
            .await
            .get(&operator_idx)
            .and_then(|m| m.get(&stake_id))
            .copied())
    }

    async fn set_pre_stake(&self, operator_idx: OperatorIdx, pre_stake: OutPoint) -> DbResult<()> {
        let mut pre_stake_table = self.pre_stake_table.write().await;
        pre_stake_table.insert(operator_idx, pre_stake);

        Ok(())
    }

    async fn get_pre_stake(&self, operator_idx: OperatorIdx) -> DbResult<Option<OutPoint>> {
        Ok(self
            .pre_stake_table
            .read()
            .await
            .get(&operator_idx)
            .copied())
    }

    async fn add_stake_data(
        &self,
        operator_idx: OperatorIdx,
        stake_index: u32,
        stake_data: StakeTxData,
    ) -> DbResult<()> {
        let mut operator_stake_data = self.stake_data.write().await;

        if let Some(data) = operator_stake_data.get_mut(&operator_idx) {
            data.insert(stake_index, stake_data);
        } else {
            let mut data = HashMap::new();
            data.insert(stake_index, stake_data);

            operator_stake_data.insert(operator_idx, data);
        }

        Ok(())
    }

    async fn get_stake_data(
        &self,
        operator_idx: OperatorIdx,
        deposit_id: u32,
    ) -> DbResult<Option<StakeTxData>> {
        Ok(self
            .stake_data
            .read()
            .await
            .get(&operator_idx)
            .and_then(|m| m.get(&deposit_id))
            .cloned())
    }

    async fn get_all_stake_data(&self, operator_idx: OperatorIdx) -> DbResult<Vec<StakeTxData>> {
        Ok(self
            .stake_data
            .read()
            .await
            .get(&operator_idx)
            .map(|map| map.values().cloned().collect())
            .unwrap_or(vec![]))
    }

    async fn register_claim_txid(
        &self,
        claim_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        self.claim_txid_to_operator_index_and_deposit_txid
            .write()
            .await
            .insert(claim_txid, (operator_idx, deposit_txid));

        Ok(())
    }

    async fn get_operator_and_deposit_for_claim(
        &self,
        claim_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        Ok(self
            .claim_txid_to_operator_index_and_deposit_txid
            .read()
            .await
            .get(claim_txid)
            .copied())
    }

    async fn register_post_assert_txid(
        &self,
        post_assert_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        self.post_assert_txid_to_operator_index_and_deposit_txid
            .write()
            .await
            .insert(post_assert_txid, (operator_idx, deposit_txid));

        Ok(())
    }

    async fn get_operator_and_deposit_for_post_assert(
        &self,
        post_assert_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        Ok(self
            .post_assert_txid_to_operator_index_and_deposit_txid
            .read()
            .await
            .get(post_assert_txid)
            .copied())
    }

    async fn register_assert_data_txids(
        &self,
        assert_data_txids: [Txid; NUM_ASSERT_DATA_TX],
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        let mut db = self
            .assert_data_txid_to_operator_index_and_deposit_txid
            .write()
            .await;

        for txid in assert_data_txids {
            db.insert(txid, (operator_idx, deposit_txid));
        }

        Ok(())
    }

    async fn get_operator_and_deposit_for_assert_data(
        &self,
        assert_data_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        Ok(self
            .assert_data_txid_to_operator_index_and_deposit_txid
            .read()
            .await
            .get(assert_data_txid)
            .copied())
    }

    async fn register_pre_assert_txid(
        &self,
        pre_assert_data_txid: Txid,
        operator_idx: OperatorIdx,
        deposit_txid: Txid,
    ) -> DbResult<()> {
        self.pre_assert_txid_to_operator_index_and_deposit_txid
            .write()
            .await
            .insert(pre_assert_data_txid, (operator_idx, deposit_txid));

        Ok(())
    }

    async fn get_operator_and_deposit_for_pre_assert(
        &self,
        pre_assert_data_txid: &Txid,
    ) -> DbResult<Option<(OperatorIdx, Txid)>> {
        Ok(self
            .pre_assert_txid_to_operator_index_and_deposit_txid
            .read()
            .await
            .get(pre_assert_data_txid)
            .copied())
    }
}
