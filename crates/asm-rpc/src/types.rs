//! Types
use serde::{Deserialize, Serialize};
use strata_asm_worker::AsmWorkerStatus;
use strata_identifiers::L1BlockCommitment;
use strata_state::asm_state::AsmState;

/// Status information for the ASM worker service.
// TODO: (@prajwolrg) Add Deserialize to AsmWorkerStatus in strata-asm-worker
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AsmWorkerStatusNew {
    /// Whether the ASM worker has been initialized.
    pub is_initialized: bool,
    /// The current L1 block commitment being processed, if any.
    pub cur_block: Option<L1BlockCommitment>,
    /// The current state of the ASM, if available.
    pub cur_state: Option<AsmState>,
}

impl From<AsmWorkerStatus> for AsmWorkerStatusNew {
    fn from(value: AsmWorkerStatus) -> Self {
        Self {
            is_initialized: value.is_initialized,
            cur_block: value.cur_block,
            cur_state: value.cur_state,
        }
    }
}
