//! Events emitted by the ASM state tracker.

use bitcoin::BlockHash;
use strata_asm_proto_bridge_v1::AssignmentEntry;
use strata_asm_proto_bridge_v1_types::SafeHarbour;

/// Snapshot of ASM-derived state fetched for a given buried Bitcoin block.
///
/// Assignments are read at the buried block (`block_hash`); the safe-harbour flag is read at the
/// ASM tip for a faster emergency response, so the two fields can reflect different heights.
#[derive(Debug, Clone)]
pub struct AsmState {
    /// Buried block hash used to query the assignment snapshot.
    pub block_hash: BlockHash,

    /// Assignment snapshot returned by the ASM for `block_hash`.
    pub assignments: Vec<AssignmentEntry>,

    /// Safe-harbour state read at the ASM tip, if the ASM returned one. `None` when the ASM has no
    /// safe harbour configured yet or the tip query could not be completed this cycle.
    pub safe_harbour: Option<SafeHarbour>,
}
