//! WorkerContext implementation for the ASM runner.

use std::sync::Arc;

use asm_storage::{AsmStateDb, MmrDb};
use bitcoin::{Block, BlockHash, Network};
use bitcoind_async_client::{Client, traits::Reader};
use strata_asm_common::{AsmManifest, AuxData};
use strata_asm_worker::{AsmState, WorkerContext, WorkerError, WorkerResult};
use strata_btc_types::{BitcoinTxid, L1BlockIdBitcoinExt, RawBitcoinTx};
use strata_identifiers::{Buf32, L1BlockCommitment, L1BlockId};
use strata_merkle::MerkleProofB32;
use tokio::runtime::Handle;

/// ASM [`WorkerContext`] implementation.
///
/// Fetches L1 blocks from a Bitcoin node and persists state via local sled storage.
pub(crate) struct AsmWorkerContext {
    runtime_handle: Handle,
    bitcoin_client: Arc<Client>,
    state_db: Arc<AsmStateDb>,
    mmr_db: Arc<MmrDb>,
}

impl AsmWorkerContext {
    pub(crate) const fn new(
        runtime_handle: Handle,
        bitcoin_client: Arc<Client>,
        state_db: Arc<AsmStateDb>,
        mmr_db: Arc<MmrDb>,
    ) -> Self {
        Self {
            runtime_handle,
            bitcoin_client,
            state_db,
            mmr_db,
        }
    }
}

impl WorkerContext for AsmWorkerContext {
    fn get_l1_block(&self, blockid: &L1BlockId) -> WorkerResult<Block> {
        let block_hash: BlockHash = blockid.to_block_hash();
        self.runtime_handle
            .block_on(self.bitcoin_client.get_block(&block_hash))
            .map_err(|_| WorkerError::MissingL1Block(*blockid))
    }

    fn get_latest_asm_state(&self) -> WorkerResult<Option<(L1BlockCommitment, AsmState)>> {
        self.state_db.get_latest().map_err(|_| WorkerError::DbError)
    }

    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> WorkerResult<AsmState> {
        self.state_db
            .get(blockid)
            .map_err(|_| WorkerError::DbError)?
            .ok_or(WorkerError::MissingAsmState(*blockid.blkid()))
    }

    fn store_anchor_state(
        &self,
        blockid: &L1BlockCommitment,
        state: &AsmState,
    ) -> WorkerResult<()> {
        self.state_db
            .put(blockid, state)
            .map_err(|_| WorkerError::DbError)
    }

    fn store_l1_manifest(&self, _manifest: AsmManifest) -> WorkerResult<()> {
        Ok(())
    }

    fn get_network(&self) -> WorkerResult<Network> {
        self.runtime_handle
            .block_on(self.bitcoin_client.network())
            .map_err(|_| WorkerError::BtcClient)
    }

    fn get_bitcoin_tx(&self, txid: &BitcoinTxid) -> WorkerResult<RawBitcoinTx> {
        let bitcoin_txid = txid.inner();
        self.runtime_handle
            .block_on(
                self.bitcoin_client
                    .get_raw_transaction_verbosity_zero(&bitcoin_txid),
            )
            .map(|resp| RawBitcoinTx::from(resp.0))
            .map_err(|_| WorkerError::BitcoinTxNotFound(*txid))
    }

    fn append_manifest_to_mmr(&self, manifest_hash: Buf32) -> WorkerResult<u64> {
        self.mmr_db
            .append_leaf(manifest_hash)
            .map_err(|_| WorkerError::DbError)
    }

    fn generate_mmr_proof_at(
        &self,
        index: u64,
        at_leaf_count: u64,
    ) -> WorkerResult<MerkleProofB32> {
        self.mmr_db
            .generate_proof(index, at_leaf_count)
            .map_err(|_| WorkerError::MmrProofFailed { index })
    }

    fn get_manifest_hash(&self, index: u64) -> WorkerResult<Option<Buf32>> {
        self.mmr_db
            .get_leaf(index)
            .map_err(|_| WorkerError::DbError)
    }

    fn store_aux_data(&self, blockid: &L1BlockCommitment, data: &AuxData) -> WorkerResult<()> {
        self.state_db
            .put_aux_data(blockid, data)
            .map_err(|_| WorkerError::DbError)
    }

    fn get_aux_data(&self, blockid: &L1BlockCommitment) -> WorkerResult<Option<AuxData>> {
        self.state_db
            .get_aux_data(blockid)
            .map_err(|_| WorkerError::DbError)
    }

    fn has_l1_manifest(&self, _blockid: &L1BlockId) -> WorkerResult<bool> {
        Ok(true)
    }
}
