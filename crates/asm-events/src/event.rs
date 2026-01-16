//! Events emitted by the ASM assignments tracker.

use bitcoin::BlockHash;
use strata_asm_proto_bridge_v1::AssignmentEntry;

/// Snapshot of assignments for a given Bitcoin block.
#[derive(Debug, Clone)]
pub struct AssignmentsState {
    /// Block hash used to query the ASM snapshot.
    pub block_hash: BlockHash,

    /// Assignment snapshot returned by the ASM.
    pub assignments: Vec<AssignmentEntry>,
}
