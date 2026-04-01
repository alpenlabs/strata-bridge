//! Executors for nag duties of the Stake State Machine.

use strata_bridge_p2p_types::{NagRequest, NagRequestPayload};
use strata_bridge_sm::stake::duties::NagDuty;
use tracing::info;

use crate::{errors::ExecutorError, output_handles::OutputHandles};

pub(crate) async fn execute_nag_duty(
    output_handles: &OutputHandles,
    nag_duty: &NagDuty,
) -> Result<(), ExecutorError> {
    let (operator_pubkey, payload) = match nag_duty {
        NagDuty::NagStakeData {
            operator_idx,
            operator_pubkey,
        } => {
            info!(%operator_idx, "nagging for missing stake data");
            let payload = NagRequestPayload::UnstakingData {
                operator_idx: *operator_idx,
            };

            (operator_pubkey.clone(), payload)
        }
        NagDuty::NagUnstakingNonces {
            operator_idx,
            operator_pubkey,
        } => {
            info!(%operator_idx, "nagging for missing unstaking nonces");
            let payload = NagRequestPayload::UnstakingNonces {
                operator_idx: *operator_idx,
            };

            (operator_pubkey.clone(), payload)
        }
        NagDuty::NagUnstakingPartials {
            operator_idx,
            operator_pubkey,
        } => {
            info!(%operator_idx, "nagging for missing unstaking partial signatures");
            let payload = NagRequestPayload::UnstakingPartials {
                operator_idx: *operator_idx,
            };

            (operator_pubkey.clone(), payload)
        }
    };

    let nag_request = NagRequest {
        recipient: operator_pubkey,
        payload,
    };

    output_handles
        .msg_handler
        .write()
        .await
        .send_nag_request(nag_request, None)
        .await;

    Ok(())
}
