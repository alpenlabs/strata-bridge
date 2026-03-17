//! Traits for the AnchorStateMachine (ASM) RPC service.

use bitcoin::BlockHash;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use strata_asm_proto_bridge_v1::{AssignmentEntry, DepositEntry};
use strata_asm_worker::AsmWorkerStatus;
use strata_checkpoint_types_ssz::CheckpointTip;

/// RPCs for retrieving ASM-derived outputs keyed by Bitcoin block hashes.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "strata_asm"))]
#[cfg_attr(feature = "client", rpc(server, client, namespace = "strata_asm"))]
pub trait AssignmentsApi {
    /// Return the assignment state for the provided Bitcoin block hash.
    #[method(name = "getAssignments")]
    async fn get_assignments(&self, block_hash: BlockHash) -> RpcResult<Vec<AssignmentEntry>>;

    /// Return the deposit state for the provided Bitcoin block hash.
    #[method(name = "getDeposits")]
    async fn get_deposits(&self, block_hash: BlockHash) -> RpcResult<Vec<DepositEntry>>;

    /// Return the status
    #[method(name = "getStatus")]
    async fn get_status(&self) -> RpcResult<AsmWorkerStatus>;

    /// Return the verified checkpoint tip for the provided Bitcoin block hash.
    #[method(name = "getCheckpointTip")]
    async fn get_checkpoint_tip(&self, block_hash: BlockHash) -> RpcResult<Option<CheckpointTip>>;
}
