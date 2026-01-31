//! WorkerContext implementation for ASM worker

use std::sync::Arc;

use bitcoin::{Block, BlockHash, Network};
use bitcoind_async_client::{Client, traits::Reader};
use strata_asm_common::AsmManifest;
use strata_asm_worker::{WorkerContext, WorkerError, WorkerResult};
use strata_btc_types::{BitcoinTxid, RawBitcoinTx};
use strata_identifiers::{Hash, L1BlockCommitment, L1BlockId};
use strata_state::asm_state::AsmState;
use strata_storage::{AsmStateManager, MmrHandle};
use tokio::runtime::Handle;

/// ASM [`WorkerContext`] implementation
///
/// This implementation fetches L1 blocks directly from a Bitcoin node
/// and uses SledDB for state storage.
pub(crate) struct AsmWorkerContext {
    runtime_handle: Handle,
    bitcoin_client: Arc<Client>,
    asm_manager: Arc<AsmStateManager>,
    mmr_handle: MmrHandle,
}

impl AsmWorkerContext {
    /// Create a new BridgeWorkerContext
    pub(crate) const fn new(
        runtime_handle: Handle,
        bitcoin_client: Arc<Client>,
        asm_manager: Arc<AsmStateManager>,
        mmr_handle: MmrHandle,
    ) -> Self {
        Self {
            runtime_handle,
            bitcoin_client,
            asm_manager,
            mmr_handle,
        }
    }
}

impl WorkerContext for AsmWorkerContext {
    fn get_l1_block(&self, blockid: &L1BlockId) -> WorkerResult<Block> {
        // Fetch block directly from Bitcoin node by hash
        let block_hash: BlockHash = (*blockid).into();
        self.runtime_handle
            .block_on(self.bitcoin_client.get_block(&block_hash))
            .map_err(|_| WorkerError::MissingL1Block(*blockid))
    }

    fn get_latest_asm_state(&self) -> WorkerResult<Option<(L1BlockCommitment, AsmState)>> {
        self.asm_manager
            .fetch_most_recent_state()
            .map_err(|_| WorkerError::DbError)
    }

    fn get_anchor_state(&self, blockid: &L1BlockCommitment) -> WorkerResult<AsmState> {
        self.asm_manager
            .get_state(*blockid)
            .map_err(|_| WorkerError::DbError)?
            .ok_or(WorkerError::MissingAsmState(*blockid.blkid()))
    }

    fn store_anchor_state(
        &self,
        blockid: &L1BlockCommitment,
        state: &AsmState,
    ) -> WorkerResult<()> {
        self.asm_manager
            .put_state(*blockid, state.clone())
            .map_err(|_| WorkerError::DbError)
    }

    fn store_l1_manifest(&self, _manifest: AsmManifest) -> WorkerResult<()> {
        // Manifests are already stored with AsmState in AsmStateManager
        // No separate storage needed for now
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
            .map_err(|_| WorkerError::BitcoinTxNotFound(txid.clone()))
    }

    fn append_manifest_to_mmr(&self, manifest_hash: Hash) -> WorkerResult<u64> {
        self.mmr_handle
            .append_leaf_blocking(manifest_hash)
            .map_err(|_| WorkerError::DbError)
    }

    fn generate_mmr_proof(&self, index: u64) -> WorkerResult<strata_merkle::MerkleProofB32> {
        self.mmr_handle
            .generate_proof(index)
            .map_err(|_| WorkerError::MmrProofFailed { index })
    }

    fn get_manifest_hash(&self, index: u64) -> WorkerResult<Option<Hash>> {
        self.mmr_handle
            .get_node_blocking(index)
            .map_err(|_| WorkerError::DbError)
    }
}
