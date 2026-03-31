//! Executors for nag duties of the Stake State Machine.

use strata_bridge_sm::stake::duties::NagDuty;

use crate::{config::ExecutionConfig, errors::ExecutorError, output_handles::OutputHandles};

pub(crate) async fn execute_nag_duty(
    _cfg: &ExecutionConfig,
    _output_handles: &OutputHandles,
    _nag_duty: &NagDuty,
) -> Result<(), ExecutorError> {
    todo!()
}
