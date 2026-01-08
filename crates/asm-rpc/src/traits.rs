//! Traits for the AnchorStateMachine (ASM) RPC service.

use bitcoin::BlockHash;
use jsonrpsee::{core::RpcResult, proc_macros::rpc};
use strata_asm_proto_bridge_v1::AssignmentEntry;

/// RPCs for retrieving ASM-derived outputs keyed by Bitcoin block hashes.
#[cfg_attr(not(feature = "client"), rpc(server, namespace = "stratabridge_asm"))]
#[cfg_attr(
    feature = "client",
    rpc(server, client, namespace = "stratabridge_asm")
)]
pub trait AssignmentsApi {
    /// Return the assignment state for the provided Bitcoin block hash.
    #[method(name = "getAssignments")]
    async fn get_assignments(&self, block_hash: BlockHash) -> RpcResult<Vec<AssignmentEntry>>;
}
