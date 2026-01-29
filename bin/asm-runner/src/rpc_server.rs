//! RPC server implementation for ASM queries

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::{BlockHash, absolute::Height};
use bitcoind_async_client::{Client, traits::Reader};
use jsonrpsee::{
    core::RpcResult,
    server::ServerBuilder,
    types::{ErrorObject, ErrorObjectOwned},
};
use strata_asm_proto_bridge_v1::{AssignmentEntry, BridgeV1State};
use strata_asm_rpc::{traits::AssignmentsApiServer, types::AsmWorkerStatusNew};
use strata_asm_txs_bridge_v1::BRIDGE_V1_SUBPROTOCOL_ID;
use strata_asm_worker::AsmWorkerHandle;
use strata_identifiers::L1BlockCommitment;
use strata_storage::AsmStateManager;
use strata_tasks::ShutdownGuard;
use tracing::info;

/// Convert any error to an RPC error
fn to_rpc_error(e: impl std::fmt::Display) -> ErrorObjectOwned {
    ErrorObject::owned(-32000, e.to_string(), None::<()>)
}

/// ASM RPC server implementation
pub(crate) struct AsmRpcServer {
    asm_manager: Arc<AsmStateManager>,
    asm_worker: Arc<AsmWorkerHandle>,
    bitcoin_client: Arc<Client>,
}

impl AsmRpcServer {
    /// Create a new ASM RPC server
    pub(crate) const fn new(
        asm_manager: Arc<AsmStateManager>,
        asm_worker: Arc<AsmWorkerHandle>,
        bitcoin_client: Arc<Client>,
    ) -> Self {
        Self {
            asm_manager,
            asm_worker,
            bitcoin_client,
        }
    }
}

impl AsmRpcServer {
    async fn to_block_commitment(
        &self,
        block_hash: BlockHash,
    ) -> anyhow::Result<L1BlockCommitment> {
        let block_id = block_hash.into();
        let height = self.bitcoin_client.get_block_height(&block_hash).await?;
        let height = Height::from_consensus(height as u32)?;
        Ok(L1BlockCommitment::new(height, block_id))
    }
}

#[async_trait]
impl AssignmentsApiServer for AsmRpcServer {
    async fn get_assignments(&self, block_hash: BlockHash) -> RpcResult<Vec<AssignmentEntry>> {
        let commitment = self
            .to_block_commitment(block_hash)
            .await
            .map_err(to_rpc_error)?;
        let state = self
            .asm_manager
            .get_state(commitment)
            .map_err(to_rpc_error)?;
        match state {
            Some(state) => {
                let bridge_state = state
                    .state()
                    .find_section(BRIDGE_V1_SUBPROTOCOL_ID)
                    .expect("bridge subprotoccol should be enabled");

                let bridge_state: BridgeV1State = borsh::from_slice(&bridge_state.data)
                    .expect("borsh deserialization should be infallible");

                Ok(bridge_state.assignments().assignments().to_vec())
            }
            None => Ok(vec![]),
        }
    }

    async fn get_status(&self) -> RpcResult<AsmWorkerStatusNew> {
        let status = self.asm_worker.monitor().get_current();
        Ok(status.into())
    }
}

/// Run the RPC server with graceful shutdown handling
pub(crate) async fn run_rpc_server(
    asm_manager: Arc<AsmStateManager>,
    asm_worker: Arc<AsmWorkerHandle>,
    bitcoin_client: Arc<Client>,
    rpc_host: String,
    rpc_port: u16,
    shutdown_guard: ShutdownGuard,
) -> Result<()> {
    let rpc_server = AsmRpcServer::new(asm_manager, asm_worker, bitcoin_client);

    let server = ServerBuilder::default()
        .build(format!("{}:{}", rpc_host, rpc_port))
        .await?;

    let rpc_handle = server.start(rpc_server.into_rpc());

    info!("ASM RPC server listening on {}:{}", rpc_host, rpc_port);

    // Wait for shutdown signal
    shutdown_guard.wait_for_shutdown().await;

    // Graceful cleanup
    info!("Stopping RPC server");
    rpc_handle.stop()?;
    rpc_handle.stopped().await;

    info!("RPC server stopped");
    Ok(())
}
