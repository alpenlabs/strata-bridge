use std::collections::{BTreeMap, HashMap, HashSet};

use async_trait::async_trait;
use bitcoin::{OutPoint, Txid};
use musig2::{PartialSignature, PubNonce, SecNonce};
use strata_bridge_primitives::types::OperatorIdx;
use tokio::sync::RwLock;

use crate::operator::{KickoffInfo, MsgHashAndOpIdToSigMap, OperatorDb};

#[derive(Debug, Default)]
pub struct OperatorDbInMemory {
    /// Txid -> OperatorIdx -> PubNonce
    collected_pubnonces: RwLock<HashMap<(Txid, u32), BTreeMap<OperatorIdx, PubNonce>>>,

    /// Txid -> PubNonce
    sec_nonces: RwLock<HashMap<(Txid, u32), SecNonce>>,

    /// (Txid, input_index) -> (Message Hash, OperatorIdx -> PartialSignature)
    collected_signatures: RwLock<HashMap<(Txid, u32), MsgHashAndOpIdToSigMap>>,

    /// OutPoints that have already been used to create KickoffTx.
    selected_outpoints: RwLock<HashSet<OutPoint>>,

    /// Deposit Txid -> PegOutGraphData
    peg_out_graphs: RwLock<BTreeMap<Txid, KickoffInfo>>,

    /// Deposit Txid (in withdrawal duty) -> latest checkpoint index
    checkpoint_table: RwLock<HashMap<Txid, u64>>,
}

#[async_trait]
impl OperatorDb for OperatorDbInMemory {
    async fn add_pubnonce(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        pubnonce: PubNonce,
    ) {
        let mut collected_pubnonces = self.collected_pubnonces.write().await;

        if let Some(pubnonce_table) = collected_pubnonces.get_mut(&(txid, input_index)) {
            pubnonce_table.insert(operator_idx, pubnonce);
        } else {
            let mut new_entry = BTreeMap::new();
            new_entry.insert(operator_idx, pubnonce);

            collected_pubnonces.insert((txid, input_index), new_entry);
        }
    }
    async fn collected_pubnonces(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> Option<BTreeMap<OperatorIdx, PubNonce>> {
        self.collected_pubnonces
            .read()
            .await
            .get(&(txid, input_index))
            .cloned()
    }

    async fn add_secnonce(&self, txid: Txid, input_index: u32, secnonce: SecNonce) {
        let mut sec_nonces = self.sec_nonces.write().await;

        sec_nonces.insert((txid, input_index), secnonce);
    }

    async fn get_secnonce(&self, txid: Txid, input_index: u32) -> Option<SecNonce> {
        self.sec_nonces
            .read()
            .await
            .get(&(txid, input_index))
            .cloned()
    }

    async fn add_message_hash_and_signature(
        &self,
        txid: Txid,
        input_index: u32,
        message_sighash: Vec<u8>,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) {
        let mut collected_sigs = self.collected_signatures.write().await;

        if let Some(sig_entry) = collected_sigs.get_mut(&(txid, input_index)) {
            sig_entry.0 = message_sighash;
            sig_entry.1.insert(operator_idx, signature);
        } else {
            let mut new_entry = (message_sighash, BTreeMap::new());
            new_entry.1.insert(operator_idx, signature);

            collected_sigs.insert((txid, input_index), new_entry);
        }
    }

    /// Adds a partial signature to the map if already present.
    async fn add_partial_signature(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) {
        let mut collected_sigs = self.collected_signatures.write().await;

        if let Some(sig_entry) = collected_sigs.get_mut(&(txid, input_index)) {
            sig_entry.1.insert(operator_idx, signature);
        }
    }

    async fn collected_signatures_per_msg(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> Option<MsgHashAndOpIdToSigMap> {
        self.collected_signatures
            .read()
            .await
            .get(&(txid, input_index))
            .cloned()
    }

    async fn add_outpoint(&self, outpoint: OutPoint) -> bool {
        let mut selected_outpoints = self.selected_outpoints.write().await;

        selected_outpoints.insert(outpoint)
    }

    async fn selected_outpoints(&self) -> HashSet<OutPoint> {
        self.selected_outpoints.read().await.clone()
    }

    async fn add_kickoff_info(&self, deposit_txid: Txid, kickoff_info: KickoffInfo) {
        let mut peg_out_graph = self.peg_out_graphs.write().await;

        peg_out_graph.insert(deposit_txid, kickoff_info);
    }

    async fn get_kickoff_info(&self, deposit_txid: Txid) -> Option<KickoffInfo> {
        self.peg_out_graphs.read().await.get(&deposit_txid).cloned()
    }

    async fn get_checkpoint_index(&self, deposit_txid: Txid) -> Option<u64> {
        self.checkpoint_table
            .read()
            .await
            .get(&deposit_txid)
            .copied()
    }

    async fn set_checkpoint_index(&self, deposit_txid: Txid, checkpoint_index: u64) {
        self.checkpoint_table
            .write()
            .await
            .insert(deposit_txid, checkpoint_index);
    }
}
