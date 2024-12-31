use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bitcoin::Txid;
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::{
    scripts::wots::{self},
    types::OperatorIdx,
};
use tokio::sync::RwLock;
use tracing::trace;

use super::errors::InMemoryError;
use crate::{errors::DbResult, public::PublicDb};

pub type TxInputToSignatureMap = HashMap<(Txid, u32), Signature>;
pub type OperatorIdxToTxInputSigMap = HashMap<OperatorIdx, TxInputToSignatureMap>;

// Assume that no node will update other nodes' data in this public db.
#[derive(Debug, Default, Clone)]
pub struct PublicDbInMemory {
    // operator_id -> deposit_txid -> WotsPublicKeys
    wots_public_keys: Arc<RwLock<HashMap<OperatorIdx, HashMap<Txid, wots::PublicKeys>>>>,

    // operator_id -> deposit_txid -> WotsSignatures
    wots_signatures: Arc<RwLock<HashMap<OperatorIdx, HashMap<Txid, wots::Signatures>>>>,

    // signature cache per txid and input index per operator
    signatures: Arc<RwLock<OperatorIdxToTxInputSigMap>>,

    // reverse mapping
    claim_txid_to_operator_index_and_deposit_txid: Arc<RwLock<HashMap<Txid, (OperatorIdx, Txid)>>>,

    pre_assert_txid_to_operator_index_and_deposit_txid:
        Arc<RwLock<HashMap<Txid, (OperatorIdx, Txid)>>>,

    assert_data_txid_to_operator_index_and_deposit_txid:
        Arc<RwLock<HashMap<Txid, (OperatorIdx, Txid)>>>,

    post_assert_txid_to_operator_index_and_deposit_txid:
        Arc<RwLock<HashMap<Txid, (OperatorIdx, Txid)>>>,
}

#[async_trait]
impl PublicDb for PublicDbInMemory {
    async fn get_wots_public_keys(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
    ) -> DbResult<wots::PublicKeys> {
        Ok(*self
            .wots_public_keys
            .read()
            .await
            .get(&operator_id)
            .ok_or(InMemoryError::NotFound)?
            .get(&deposit_txid)
            .ok_or(InMemoryError::NotFound)?)
    }

    async fn get_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
    ) -> DbResult<wots::Signatures> {
        Ok(*self
            .wots_signatures
            .read()
            .await
            .get(&operator_id)
            .ok_or(InMemoryError::NotFound)?
            .get(&deposit_txid)
            .ok_or(InMemoryError::NotFound)?)
    }

    async fn set_wots_public_keys(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        public_keys: &wots::PublicKeys,
    ) -> DbResult<()> {
        trace!(action = "trying to acquire wlock on wots public keys", %operator_id, %deposit_txid);
        let mut map = self.wots_public_keys.write().await;
        trace!(event = "wlock acquired on wots public keys", %operator_id, %deposit_txid);

        if let Some(op_keys) = map.get_mut(&operator_id) {
            op_keys.insert(deposit_txid, *public_keys);
        } else {
            let mut keys = HashMap::new();
            keys.insert(deposit_txid, *public_keys);

            map.insert(operator_id, keys);
        }

        Ok(())
    }

    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Signature> {
        Ok(self
            .signatures
            .read()
            .await
            .get(&operator_idx)
            .ok_or(InMemoryError::NotFound)?
            .get(&(txid, input_index))
            .copied()
            .ok_or(InMemoryError::NotFound)?)
    }

    async fn set_wots_signatures(
        &self,
        operator_id: u32,
        deposit_txid: Txid,
        signatures: &wots::Signatures,
    ) -> DbResult<()> {
        trace!(action = "trying to acquire wlock on wots signatures", %operator_id, %deposit_txid);
        let mut map = self.wots_signatures.write().await;
        trace!(event = "wlock acquired on wots signatures", %operator_id, %deposit_txid);

        if let Some(op_keys) = map.get_mut(&operator_id) {
            op_keys.insert(deposit_txid, *signatures);
        } else {
            let mut sigs_map = HashMap::new();
            sigs_map.insert(deposit_txid, *signatures);

            map.insert(operator_id, sigs_map);
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
        assert_data_txids: [Txid; 7],
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
