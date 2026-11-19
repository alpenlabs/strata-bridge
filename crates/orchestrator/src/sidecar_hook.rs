//! The sidecar hook: an optional decision on actions this node takes on its own.
//!
//! With a hook attached through
//! [`Pipeline::with_sidecar_hook`](crate::pipeline::Pipeline::with_sidecar_hook), the node holds
//! every newly registered deposit request in [`DepositState::ParticipationPending`] until the
//! hook decides whether this node takes part. Without one, the node behaves as before.
//!
//! A decision only controls this node's own participation. The deposit index is allocated as
//! usual, so indices stay aligned across operators, and a held deposit keeps observing Bitcoin.

use std::fmt;

use bitcoin::{Amount, OutPoint};
use strata_bridge_primitives::{covenant::CovenantId, types::DepositIdx};
use strata_bridge_sm::deposit::state::DepositState;

use crate::sm_registry::SMRegistry;

/// A deposit request this node is asked to take part in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DepositParticipationRequest {
    /// The deposit index allocated to the request.
    pub deposit_idx: DepositIdx,
    /// The covenant the deposit was registered under.
    pub covenant: CovenantId,
    /// The deposit request output.
    pub deposit_request_outpoint: OutPoint,
    /// The amount the deposit locks in the bridge.
    pub amount: Amount,
}

/// A decision on taking part in a deposit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParticipationDecision {
    /// Take part: build this deposit's graphs and sign.
    Participate,
    /// Do not take part. The deposit becomes [`DepositState::ParticipationDeclined`].
    Decline,
}

/// A sidecar hook that decides whether this node takes part in a deposit.
///
/// The pipeline asks after every committed batch, once for each deposit waiting for a decision,
/// so an implementation must answer from memory and must not block. One that needs I/O starts it
/// in the background, returns `None` meanwhile, and sends on the wake-up channel given to
/// [`Pipeline::with_sidecar_hook`](crate::pipeline::Pipeline::with_sidecar_hook) once it has an
/// answer. Asking again for a request it is already evaluating must not start a second
/// evaluation.
///
/// The pipeline applies a decision once and persists the result, so a later answer for the same
/// deposit changes nothing.
pub trait SidecarHook: fmt::Debug + Send + Sync {
    /// Returns the decision on taking part in `request`, or `None` if there is none yet.
    fn deposit_participation(
        &self,
        request: &DepositParticipationRequest,
    ) -> Option<ParticipationDecision>;
}

/// Asks `hook` about every deposit waiting for a participation decision and returns the
/// decisions that are ready.
///
/// Nothing is asked while safe harbour is active: the safe-harbour scan aborts held deposits.
pub(crate) fn ready_participation_decisions(
    registry: &SMRegistry,
    hook: &dyn SidecarHook,
) -> Vec<(DepositIdx, ParticipationDecision)> {
    if registry.safe_harbour_active() {
        return Vec::new();
    }
    let amount = registry.cfg().deposit.deposit_amount();
    registry
        .deposits()
        .filter(|(_, sm)| matches!(sm.state(), DepositState::ParticipationPending { .. }))
        .filter_map(|(&deposit_idx, sm)| {
            let request = DepositParticipationRequest {
                deposit_idx,
                covenant: sm.context().covenant(),
                deposit_request_outpoint: sm.context().deposit_request_outpoint(),
                amount,
            };
            hook.deposit_participation(&request)
                .map(|decision| (deposit_idx, decision))
        })
        .collect()
}

#[cfg(test)]
pub(crate) mod testing {
    use std::{collections::BTreeMap, sync::Mutex};

    use super::*;

    /// A hook that answers from a fixed table and records every request it is asked about.
    #[derive(Debug, Default)]
    pub(crate) struct FixedHook {
        decisions: Mutex<BTreeMap<DepositIdx, ParticipationDecision>>,
        asked: Mutex<Vec<DepositParticipationRequest>>,
    }

    impl FixedHook {
        /// Answers `decision` for `deposit_idx` from now on.
        pub(crate) fn decide(&self, deposit_idx: DepositIdx, decision: ParticipationDecision) {
            self.decisions.lock().unwrap().insert(deposit_idx, decision);
        }

        /// Returns every request asked so far, in order.
        pub(crate) fn asked(&self) -> Vec<DepositParticipationRequest> {
            self.asked.lock().unwrap().clone()
        }
    }

    impl SidecarHook for FixedHook {
        fn deposit_participation(
            &self,
            request: &DepositParticipationRequest,
        ) -> Option<ParticipationDecision> {
            self.asked.lock().unwrap().push(*request);
            self.decisions
                .lock()
                .unwrap()
                .get(&request.deposit_idx)
                .copied()
        }
    }
}
