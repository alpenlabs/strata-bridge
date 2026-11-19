//! The sidecar hook: an optional decision on actions this node takes on its own.
//!
//! With a hook attached through
//! [`Pipeline::with_sidecar_hook`](crate::pipeline::Pipeline::with_sidecar_hook), the node waits
//! for the hook before two of its own actions. Without one, the node behaves as before.
//!
//! - **Taking part in a deposit.** Every newly registered deposit request is held in
//!   [`DepositState::ParticipationPending`] until the hook decides. The deposit index is allocated
//!   as usual, so indices stay aligned across operators, and a held deposit keeps observing
//!   Bitcoin.
//! - **Paying a withdrawal assigned to this node.** A `FulfillWithdrawalRequest` duty is held in
//!   memory, before dispatch, until the hook approves it. The state machine emits the duty again
//!   whenever ASM re-delivers the assignment (in practice every buried block) and on every retry
//!   tick, and each emission is checked again, so an approval is only ever used for the attempt it
//!   was given for.
//!
//! A decision only controls this node's own action: observation and defensive duties continue.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

use bitcoin::{Amount, OutPoint};
use bitcoin_bosd::Descriptor;
use strata_bridge_primitives::{
    covenant::CovenantId,
    types::{BitcoinBlockHeight, DepositIdx, OperatorIdx},
};
use strata_bridge_sm::deposit::{duties::DepositDuty, state::DepositState};
use tracing::{debug, info};

use crate::{sm_registry::SMRegistry, sm_types::UnifiedDuty};

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

/// A withdrawal this node is assigned to pay.
///
/// Built from the fulfillment duty's own fields, so a changed assignment (new deadline or
/// destination) is a different request and carries no earlier approval. Together the fields
/// identify the assignment completely, so the hook can check it against ASM before it decides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WithdrawalFulfillmentRequest {
    /// The deposit whose withdrawal is being paid.
    pub deposit_idx: DepositIdx,
    /// The covenant the deposit was registered under.
    pub covenant: CovenantId,
    /// The block height by which this node must pay.
    pub deadline: BitcoinBlockHeight,
    /// Where the payment goes.
    pub destination: Descriptor,
    /// The deposit amount; the user receives it minus the operator fee.
    pub amount: Amount,
    /// The operator ASM assigned the withdrawal to: this node.
    pub assignee: OperatorIdx,
    /// The operator fee this node deducts from the payment, from its deposit configuration.
    pub operator_fee: Amount,
}

/// A decision on paying a withdrawal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FulfillmentDecision {
    /// Pay: dispatch the fulfillment duty.
    Fulfill,
    /// Do not pay. The duty stays held; ASM reassigns the withdrawal after its deadline.
    Decline,
}

/// A sidecar hook that decides whether this node takes part in a deposit and whether it pays a
/// withdrawal assigned to it.
///
/// The pipeline asks after every committed batch about each action waiting for a decision, so
/// an implementation must answer from memory and must not block. One that needs I/O starts it
/// in the background, returns `None` meanwhile, and sends on the wake-up channel given to
/// [`Pipeline::with_sidecar_hook`](crate::pipeline::Pipeline::with_sidecar_hook) once it has an
/// answer. Asking again for a request it is already evaluating must not start a second
/// evaluation.
///
/// A deposit decision is applied once and persisted, so a later answer for the same deposit
/// changes nothing. A withdrawal approval is checked each time the duty is dispatched; the
/// executor does not ask again while it pays.
pub trait SidecarHook: fmt::Debug + Send + Sync {
    /// Returns the decision on taking part in `request`, or `None` if there is none yet.
    fn deposit_participation(
        &self,
        request: &DepositParticipationRequest,
    ) -> Option<ParticipationDecision>;

    /// Returns the decision on paying `request`, or `None` if there is none yet.
    fn withdrawal_fulfillment(
        &self,
        request: &WithdrawalFulfillmentRequest,
    ) -> Option<FulfillmentDecision>;
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

/// Fulfillment duties waiting for the hook's approval, by deposit index.
///
/// Held in memory only: the state machine emits the duty again whenever ASM re-delivers the
/// assignment and on every retry tick (which also fires at startup), so nothing is lost across a
/// restart.
#[derive(Debug, Default)]
pub(crate) struct HeldFulfillments {
    held: BTreeMap<DepositIdx, UnifiedDuty>,
}

/// The duties a [`HeldFulfillments::gate`] pass lets through.
#[derive(Debug, Default)]
pub(crate) struct GatedDuties {
    /// The batch's own duties, minus the fulfillments still waiting for approval.
    pub(crate) ready: Vec<UnifiedDuty>,
    /// Fulfillments held from earlier batches that the hook now approves. They answer nothing in
    /// this batch, so they must not be dispatched as a reply to its nag.
    pub(crate) released: Vec<UnifiedDuty>,
}

impl HeldFulfillments {
    /// Gates a batch's duties and releases earlier held ones, asking the hook once per
    /// fulfillment.
    ///
    /// Every duty except a fulfillment passes. A fulfillment the hook approves passes and drops
    /// any held copy for its deposit; one it does not approve replaces the held copy. A
    /// fulfillment that no longer matches its deposit's assignment is dropped, held or not, so it
    /// is never paid without an approval. While safe harbour is active nothing is asked or held:
    /// the dispatcher suppresses withdrawal duties anyway.
    ///
    /// `funded` lists the deposits whose withdrawal this node already funded under an earlier
    /// approval. Their fulfillment passes without asking the hook: the executor finishes or
    /// re-drives the payment it committed to, for example after a restart, instead of leaving a
    /// public payment without fee bumps until the hook answers again.
    pub(crate) fn gate(
        &mut self,
        duties: Vec<UnifiedDuty>,
        funded: &BTreeSet<DepositIdx>,
        registry: &SMRegistry,
        hook: &dyn SidecarHook,
    ) -> GatedDuties {
        if registry.safe_harbour_active() {
            self.held.clear();
            return GatedDuties {
                ready: duties,
                released: Vec::new(),
            };
        }
        let mut gated = GatedDuties::default();
        let mut asked = BTreeSet::new();
        for duty in duties {
            let UnifiedDuty::Deposit(DepositDuty::FulfillWithdrawalRequest { deposit_idx, .. }) =
                &duty
            else {
                gated.ready.push(duty);
                continue;
            };
            let deposit_idx = *deposit_idx;
            let Some(request) = fulfillment_request(&duty, registry) else {
                debug!(%deposit_idx, "dropping a withdrawal fulfillment that is no longer current");
                continue;
            };
            asked.insert(deposit_idx);
            if funded.contains(&deposit_idx) {
                debug!(%deposit_idx, "withdrawal already funded; dispatching without asking the sidecar hook");
                self.held.remove(&deposit_idx);
                gated.ready.push(duty);
                continue;
            }
            match hook.withdrawal_fulfillment(&request) {
                Some(FulfillmentDecision::Fulfill) => {
                    self.held.remove(&deposit_idx);
                    gated.ready.push(duty);
                }
                decision => {
                    debug!(%deposit_idx, ?decision, "holding withdrawal fulfillment for the sidecar hook");
                    self.held.insert(deposit_idx, duty);
                }
            }
        }
        self.held.retain(|&deposit_idx, duty| {
            if asked.contains(&deposit_idx) {
                return true;
            }
            let Some(request) = fulfillment_request(duty, registry) else {
                debug!(%deposit_idx, "dropping a held withdrawal fulfillment that is no longer current");
                return false;
            };
            if hook.withdrawal_fulfillment(&request) != Some(FulfillmentDecision::Fulfill) {
                return true;
            }
            info!(%deposit_idx, "sidecar hook approved the withdrawal fulfillment");
            gated.released.push(duty.clone());
            false
        });
        gated
    }
}

/// The deposit whose withdrawal `duty` fulfills, if it is a fulfillment duty.
pub(crate) const fn fulfillment_deposit(duty: &UnifiedDuty) -> Option<DepositIdx> {
    match duty {
        UnifiedDuty::Deposit(DepositDuty::FulfillWithdrawalRequest { deposit_idx, .. }) => {
            Some(*deposit_idx)
        }
        _ => None,
    }
}

/// The request for a fulfillment duty that is still current: its deposit is `Assigned` to this
/// node with the duty's deadline and destination. `None` for any other duty.
fn fulfillment_request(
    duty: &UnifiedDuty,
    registry: &SMRegistry,
) -> Option<WithdrawalFulfillmentRequest> {
    let UnifiedDuty::Deposit(DepositDuty::FulfillWithdrawalRequest {
        deposit_idx,
        deadline,
        recipient_desc,
        deposit_amount,
    }) = duty
    else {
        return None;
    };
    let sm = registry.get_deposit(deposit_idx)?;
    let DepositState::Assigned {
        assignee,
        deadline: assigned_deadline,
        recipient_desc: assigned_recipient,
        ..
    } = sm.state()
    else {
        return None;
    };
    (*assignee == sm.context().operator_table().pov_idx()
        && assigned_deadline == deadline
        && assigned_recipient == recipient_desc)
        .then(|| WithdrawalFulfillmentRequest {
            deposit_idx: *deposit_idx,
            covenant: sm.context().covenant(),
            deadline: *deadline,
            destination: recipient_desc.clone(),
            amount: *deposit_amount,
            assignee: *assignee,
            operator_fee: registry.cfg().deposit.operator_fee(),
        })
}

#[cfg(test)]
pub(crate) mod testing {
    use std::{collections::BTreeMap, sync::Mutex};

    use super::*;

    /// A hook that answers from fixed tables and records every request it is asked about.
    #[derive(Debug, Default)]
    pub(crate) struct FixedHook {
        decisions: Mutex<BTreeMap<DepositIdx, ParticipationDecision>>,
        asked: Mutex<Vec<DepositParticipationRequest>>,
        /// Keyed on the full request, so a changed assignment needs its own decision.
        fulfillments: Mutex<Vec<(WithdrawalFulfillmentRequest, FulfillmentDecision)>>,
        asked_fulfillments: Mutex<Vec<WithdrawalFulfillmentRequest>>,
    }

    impl FixedHook {
        /// Answers `decision` for `deposit_idx` from now on.
        pub(crate) fn decide(&self, deposit_idx: DepositIdx, decision: ParticipationDecision) {
            self.decisions.lock().unwrap().insert(deposit_idx, decision);
        }

        /// Returns every participation request asked so far, in order.
        pub(crate) fn asked(&self) -> Vec<DepositParticipationRequest> {
            self.asked.lock().unwrap().clone()
        }

        /// Answers `decision` for exactly `request` from now on.
        pub(crate) fn decide_fulfillment(
            &self,
            request: WithdrawalFulfillmentRequest,
            decision: FulfillmentDecision,
        ) {
            let mut fulfillments = self.fulfillments.lock().unwrap();
            fulfillments.retain(|(known, _)| *known != request);
            fulfillments.push((request, decision));
        }

        /// Returns every fulfillment request asked so far, in order.
        pub(crate) fn asked_fulfillments(&self) -> Vec<WithdrawalFulfillmentRequest> {
            self.asked_fulfillments.lock().unwrap().clone()
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

        fn withdrawal_fulfillment(
            &self,
            request: &WithdrawalFulfillmentRequest,
        ) -> Option<FulfillmentDecision> {
            self.asked_fulfillments
                .lock()
                .unwrap()
                .push(request.clone());
            self.fulfillments
                .lock()
                .unwrap()
                .iter()
                .find(|(known, _)| known == request)
                .map(|(_, decision)| *decision)
        }
    }
}

#[cfg(test)]
mod tests {
    use strata_bridge_sm::deposit::duties::DepositDuty;

    use super::{testing::FixedHook, *};
    use crate::testing::{
        TEST_DEPOSIT_AMOUNT, TEST_POV_IDX, insert_deposit_activated_at, random_p2tr_desc,
        test_empty_registry, test_safe_harbour_address,
    };

    const DEADLINE: BitcoinBlockHeight = 1_000;

    /// A registry with deposit 0 assigned to `assignee`, due at `deadline`, paying `recipient`.
    fn assigned(
        assignee: OperatorIdx,
        deadline: BitcoinBlockHeight,
        recipient: &Descriptor,
    ) -> SMRegistry {
        let mut registry = test_empty_registry();
        insert_deposit_activated_at(&mut registry, 0, 100);
        assign(&mut registry, assignee, deadline, recipient);
        registry
    }

    fn assign(
        registry: &mut SMRegistry,
        assignee: OperatorIdx,
        deadline: BitcoinBlockHeight,
        recipient: &Descriptor,
    ) {
        registry.get_deposit_mut(&0).unwrap().state = DepositState::Assigned {
            last_block_height: 200,
            assignee,
            deadline,
            recipient_desc: recipient.clone(),
        };
    }

    fn fulfillment(deadline: BitcoinBlockHeight, recipient: &Descriptor) -> UnifiedDuty {
        UnifiedDuty::Deposit(DepositDuty::FulfillWithdrawalRequest {
            deposit_idx: 0,
            deadline,
            recipient_desc: recipient.clone(),
            deposit_amount: TEST_DEPOSIT_AMOUNT,
        })
    }

    /// The request the pipeline builds for deposit 0's fulfillment.
    fn request(
        registry: &SMRegistry,
        deadline: BitcoinBlockHeight,
        recipient: &Descriptor,
    ) -> WithdrawalFulfillmentRequest {
        WithdrawalFulfillmentRequest {
            deposit_idx: 0,
            covenant: registry.get_deposit(&0).unwrap().context().covenant(),
            deadline,
            destination: recipient.clone(),
            amount: TEST_DEPOSIT_AMOUNT,
            assignee: TEST_POV_IDX,
            operator_fee: registry.cfg().deposit.operator_fee(),
        }
    }

    fn is_fulfillment_of_deposit_0(duties: &[UnifiedDuty]) -> bool {
        matches!(
            duties,
            [UnifiedDuty::Deposit(
                DepositDuty::FulfillWithdrawalRequest { deposit_idx: 0, .. }
            )]
        )
    }

    #[test]
    fn other_duties_pass_without_asking_the_hook() {
        let recipient = random_p2tr_desc();
        let registry = assigned(TEST_POV_IDX, DEADLINE, &recipient);
        let hook = FixedHook::default();
        let other = UnifiedDuty::Deposit(DepositDuty::RequestPayoutNonces {
            deposit_idx: 0,
            pov_operator_idx: TEST_POV_IDX,
            payout_descriptor: None,
        });

        let gated =
            HeldFulfillments::default().gate(vec![other], &BTreeSet::new(), &registry, &hook);
        assert_eq!(gated.ready.len(), 1);
        assert!(gated.released.is_empty());
        assert!(hook.asked_fulfillments().is_empty());
    }

    #[test]
    fn an_unapproved_fulfillment_is_held_and_released_on_its_own_once_approved() {
        let recipient = random_p2tr_desc();
        let registry = assigned(TEST_POV_IDX, DEADLINE, &recipient);
        let hook = FixedHook::default();
        let mut held = HeldFulfillments::default();

        let gated = held.gate(
            vec![fulfillment(DEADLINE, &recipient)],
            &BTreeSet::new(),
            &registry,
            &hook,
        );
        assert!(gated.ready.is_empty() && gated.released.is_empty());
        assert_eq!(
            hook.asked_fulfillments(),
            vec![request(&registry, DEADLINE, &recipient)],
            "asked once, about a request built from the duty's own fields"
        );
        assert!(
            held.gate(vec![], &BTreeSet::new(), &registry, &hook)
                .released
                .is_empty()
        );

        hook.decide_fulfillment(
            request(&registry, DEADLINE, &recipient),
            FulfillmentDecision::Fulfill,
        );
        // A later batch, for example a nag reply, carries its own duties. The released payment
        // comes back separately, so it is never dispatched as a reply to that nag.
        let other = UnifiedDuty::Deposit(DepositDuty::RequestPayoutNonces {
            deposit_idx: 1,
            pov_operator_idx: TEST_POV_IDX,
            payout_descriptor: None,
        });
        let gated = held.gate(vec![other], &BTreeSet::new(), &registry, &hook);
        assert_eq!(gated.ready.len(), 1, "only the batch's own duty");
        assert!(is_fulfillment_of_deposit_0(&gated.released));
        assert!(
            held.gate(vec![], &BTreeSet::new(), &registry, &hook)
                .released
                .is_empty(),
            "released once"
        );
    }

    #[test]
    fn an_approved_fulfillment_passes_and_replaces_its_held_copy() {
        let recipient = random_p2tr_desc();
        let registry = assigned(TEST_POV_IDX, DEADLINE, &recipient);
        let hook = FixedHook::default();
        let mut held = HeldFulfillments::default();
        assert!(
            held.gate(
                vec![fulfillment(DEADLINE, &recipient)],
                &BTreeSet::new(),
                &registry,
                &hook
            )
            .ready
            .is_empty()
        );

        // The state machine emits the duty again; by now the hook approves it.
        hook.decide_fulfillment(
            request(&registry, DEADLINE, &recipient),
            FulfillmentDecision::Fulfill,
        );
        let gated = held.gate(
            vec![fulfillment(DEADLINE, &recipient)],
            &BTreeSet::new(),
            &registry,
            &hook,
        );
        assert!(is_fulfillment_of_deposit_0(&gated.ready));
        assert!(
            gated.released.is_empty(),
            "the held copy is not dispatched a second time"
        );
        assert_eq!(hook.asked_fulfillments().len(), 2, "asked once per batch");
        assert!(held.held.is_empty());
    }

    #[test]
    fn an_approval_does_not_carry_over_to_a_changed_assignment() {
        let recipient = random_p2tr_desc();
        let mut registry = assigned(TEST_POV_IDX, DEADLINE, &recipient);
        let hook = FixedHook::default();
        hook.decide_fulfillment(
            request(&registry, DEADLINE, &recipient),
            FulfillmentDecision::Decline,
        );
        let mut held = HeldFulfillments::default();
        assert!(
            held.gate(
                vec![fulfillment(DEADLINE, &recipient)],
                &BTreeSet::new(),
                &registry,
                &hook
            )
            .ready
            .is_empty(),
            "declined: held"
        );

        // ASM reassigns the withdrawal to this node with a new deadline. The old request is now
        // approved, but nothing for it is paid: its held duty is stale.
        let new_deadline = DEADLINE + 530;
        assign(&mut registry, TEST_POV_IDX, new_deadline, &recipient);
        hook.decide_fulfillment(
            request(&registry, DEADLINE, &recipient),
            FulfillmentDecision::Fulfill,
        );
        let gated = held.gate(
            vec![fulfillment(new_deadline, &recipient)],
            &BTreeSet::new(),
            &registry,
            &hook,
        );
        assert!(gated.ready.is_empty(), "the new request has no approval");
        assert!(gated.released.is_empty(), "the stale duty is never paid");

        hook.decide_fulfillment(
            request(&registry, new_deadline, &recipient),
            FulfillmentDecision::Fulfill,
        );
        let gated = held.gate(vec![], &BTreeSet::new(), &registry, &hook);
        assert!(is_fulfillment_of_deposit_0(&gated.released));
    }

    #[test]
    fn a_fulfillment_that_no_longer_matches_its_assignment_is_dropped() {
        let recipient = random_p2tr_desc();
        let hook = FixedHook::default();

        for registry in [
            assigned(TEST_POV_IDX + 1, DEADLINE, &recipient),
            assigned(TEST_POV_IDX, DEADLINE, &random_p2tr_desc()),
        ] {
            hook.decide_fulfillment(
                request(&registry, DEADLINE, &recipient),
                FulfillmentDecision::Fulfill,
            );
            let mut held = HeldFulfillments::default();
            let gated = held.gate(
                vec![fulfillment(DEADLINE, &recipient)],
                &BTreeSet::new(),
                &registry,
                &hook,
            );
            assert!(
                gated.ready.is_empty() && gated.released.is_empty(),
                "never paid without an approval for the current assignment"
            );
            assert!(held.held.is_empty());
        }
        assert!(hook.asked_fulfillments().is_empty());
    }

    #[test]
    fn an_already_funded_fulfillment_passes_without_asking_the_hook() {
        let recipient = random_p2tr_desc();
        let registry = assigned(TEST_POV_IDX, DEADLINE, &recipient);
        let hook = FixedHook::default();
        hook.decide_fulfillment(
            request(&registry, DEADLINE, &recipient),
            FulfillmentDecision::Decline,
        );
        let mut held = HeldFulfillments::default();
        assert!(
            held.gate(
                vec![fulfillment(DEADLINE, &recipient)],
                &BTreeSet::new(),
                &registry,
                &hook
            )
            .ready
            .is_empty(),
            "not funded yet: the decline holds it"
        );

        // After a restart, the payment this node funded under an earlier approval is in the
        // mempool. Its next emission must reach the executor, which re-drives it.
        let funded = BTreeSet::from([0]);
        let asked_before = hook.asked_fulfillments().len();
        let gated = held.gate(
            vec![fulfillment(DEADLINE, &recipient)],
            &funded,
            &registry,
            &hook,
        );
        assert!(is_fulfillment_of_deposit_0(&gated.ready));
        assert!(gated.released.is_empty());
        assert_eq!(hook.asked_fulfillments().len(), asked_before, "not asked");
        assert!(held.held.is_empty(), "the held copy is dropped");
    }

    #[test]
    fn an_already_funded_fulfillment_is_still_dropped_once_its_assignment_moves() {
        let recipient = random_p2tr_desc();
        let registry = assigned(TEST_POV_IDX + 1, DEADLINE, &recipient);
        let hook = FixedHook::default();
        let gated = HeldFulfillments::default().gate(
            vec![fulfillment(DEADLINE, &recipient)],
            &BTreeSet::from([0]),
            &registry,
            &hook,
        );
        assert!(gated.ready.is_empty() && gated.released.is_empty());
    }

    #[test]
    fn nothing_is_asked_or_held_under_safe_harbour() {
        let recipient = random_p2tr_desc();
        let mut registry = assigned(TEST_POV_IDX, DEADLINE, &recipient);
        let hook = FixedHook::default();
        let mut held = HeldFulfillments::default();
        assert!(
            held.gate(
                vec![fulfillment(DEADLINE, &recipient)],
                &BTreeSet::new(),
                &registry,
                &hook
            )
            .ready
            .is_empty()
        );

        registry.activate_safe_harbour(test_safe_harbour_address());
        hook.decide_fulfillment(
            request(&registry, DEADLINE, &recipient),
            FulfillmentDecision::Fulfill,
        );
        let gated = held.gate(
            vec![fulfillment(DEADLINE, &recipient)],
            &BTreeSet::new(),
            &registry,
            &hook,
        );
        assert!(
            is_fulfillment_of_deposit_0(&gated.ready),
            "passed through: the dispatcher suppresses it under safe harbour"
        );
        assert!(gated.released.is_empty());
        assert!(held.held.is_empty());
        assert_eq!(
            hook.asked_fulfillments().len(),
            1,
            "only before safe harbour"
        );
    }
}
