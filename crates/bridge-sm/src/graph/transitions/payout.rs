use bitcoin::{Txid, hashes::Hash};
use tracing::{info, warn};

use crate::{
    graph::{
        errors::{GSMError, GSMResult},
        events::{PayoutConfirmedEvent, PayoutConnectorSpentEvent},
        machine::{GSMOutput, GraphSM},
        state::{AbortReason, GraphState},
    },
    tx_classifier::is_payout_connector_spent,
};

impl GraphSM {
    /// Processes the event where a payout transaction has been confirmed
    /// on-chain.
    pub(crate) fn process_payout(
        &mut self,
        payout_event: PayoutConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state() {
            GraphState::Claimed { graph_summary, .. } => {
                if payout_event.payout_txid != graph_summary.uncontested_payout {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        payout_event.into(),
                        "Invalid uncontested payout transaction",
                    ));
                }

                self.state = GraphState::Withdrawn {
                    claim_txid: graph_summary.claim,
                    payout_txid: payout_event.payout_txid,
                };

                Ok(GSMOutput::new())
            }
            GraphState::Contested { graph_summary, .. } => {
                if payout_event.payout_txid != graph_summary.contested_payout {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        payout_event.into(),
                        "Invalid contested payout transaction",
                    ));
                }

                warn!(
                    graph_idx = ?self.context().graph_idx(),
                    payout_txid = %payout_event.payout_txid,
                    "Contested payout posted in contested state"
                );

                self.state = GraphState::Withdrawn {
                    claim_txid: graph_summary.claim,
                    payout_txid: payout_event.payout_txid,
                };

                Ok(GSMOutput::new())
            }
            GraphState::BridgeProofPosted { graph_summary, .. } => {
                if payout_event.payout_txid != graph_summary.contested_payout {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        payout_event.into(),
                        "Invalid contested payout transaction",
                    ));
                }

                info!(
                    graph_idx = ?self.context().graph_idx(),
                    payout_txid = %payout_event.payout_txid,
                    "Contested payout posted after bridge proof"
                );

                self.state = GraphState::Withdrawn {
                    claim_txid: graph_summary.claim,
                    payout_txid: payout_event.payout_txid,
                };

                Ok(GSMOutput::new())
            }
            GraphState::AllNackd {
                claim_txid,
                expected_payout_txid,
                ..
            } => {
                if payout_event.payout_txid != *expected_payout_txid {
                    return Err(GSMError::rejected(
                        self.state().clone(),
                        payout_event.into(),
                        "Invalid contested payout transaction",
                    ));
                }

                warn!(
                    graph_idx = ?self.context().graph_idx(),
                    payout_txid = %payout_event.payout_txid,
                    "payout posted after all counterproofs were Nack'd"
                );

                self.state = GraphState::Withdrawn {
                    claim_txid: *claim_txid,
                    payout_txid: payout_event.payout_txid,
                };

                Ok(GSMOutput::new())
            }
            GraphState::Withdrawn { .. } => Err(GSMError::duplicate(
                self.state().clone(),
                payout_event.into(),
            )),
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                payout_event.into(),
                None,
            )),
        }
    }

    /// Processes the event where the payout connector has been spent by a
    /// transaction other than the legitimate payouts.
    ///
    /// Note: The ordering of payout checks vs payout connector spent checks is
    /// enforced by the tx_classifier, which checks for valid payout transactions
    /// before checking for payout connector spend.
    pub(crate) fn process_payout_connector_spent(
        &mut self,
        event: PayoutConnectorSpentEvent,
    ) -> GSMResult<GSMOutput> {
        // Defensive guard: the classifier emits this event only for txs that
        // consume the payout-connector outpoint of the current state's claim.
        // Verify the invariant here as well so misrouted or directly-injected
        // events cannot record `payout_connector_spent` or terminalize the
        // graph. The connector outpoint is rooted at the claim txid, which
        // only exists from `Claimed` onward.
        let claim_txid = match self.state() {
            GraphState::Claimed { graph_summary, .. }
            | GraphState::Contested { graph_summary, .. }
            | GraphState::BridgeProofPosted { graph_summary, .. }
            | GraphState::CounterProofPosted { graph_summary, .. } => Some(graph_summary.claim),
            GraphState::BridgeProofTimedout { claim_txid, .. }
            | GraphState::Acked { claim_txid, .. }
            | GraphState::AllNackd { claim_txid, .. } => Some(*claim_txid),
            _ => None,
        };
        if let Some(claim_txid) = claim_txid
            && !is_payout_connector_spent(&claim_txid, &event.tx)
        {
            return Err(GSMError::rejected(
                self.state.clone(),
                event.into(),
                "connector spent event tx does not spend the payout connector outpoint",
            ));
        }

        let spending_txid = event.tx.compute_txid();

        // The legitimate uncontested/contested payout consumes the same
        // connector outpoint; if such a tx is misrouted to this STF (rather
        // than `process_payout`), reject it so the graph is not aborted on
        // a benign payout.
        if is_payout_tx(self.state(), &spending_txid) {
            return Err(GSMError::rejected(
                self.state.clone(),
                event.into(),
                "connector spent event tx is the legitimate payout for this state",
            ));
        }

        // A connector spend is already recorded: matching txid is a
        // duplicate re-delivery; any other txid is rejected.
        if let Some(recorded) = self.state.payout_connector_spent_txid() {
            if recorded == spending_txid {
                return Err(GSMError::duplicate(self.state().clone(), event.into()));
            }
            return Err(GSMError::rejected(
                self.state().clone(),
                event.into(),
                "connector already recorded with a different spending txid",
            ));
        }

        // Two-fact post-`Claimed` state with the stake already gone:
        // can't get payout and can't get slashed now, only thing to do is
        // abort.
        if let Some(stake_spending_txid) = self.state.stake_spent_txid() {
            self.state = GraphState::Aborted {
                claim_txid: self.state.claim_txid().unwrap_or(Txid::all_zeros()),
                reason: AbortReason::Both {
                    stake_spending_txid,
                    payout_connector_spending_txid: spending_txid,
                },
            };
            return Ok(GSMOutput::new());
        }

        // Two-fact post-`Claimed` state with neither field set yet: record
        // the connector spend and stay. The GSM will react to a subsequent
        // stake spend.
        if self.state.set_payout_connector_spent(spending_txid) {
            return Ok(GSMOutput::new());
        }

        // States without a `payout_connector_spent` field:
        // - `AllNackd`: the only remaining payout path uses the connector, so a connector spend
        //   here makes payout impossible — abort directly.
        // - `BridgeProofTimedout` / `Acked`: the only remaining path is slash (independent of the
        //   connector), so a connector spend is irrelevant — reject as no-op.
        // - pre-`Claimed`: the connector does not exist yet, so the classifier should never emit
        //   this event from these states; if it does, treat it as a protocol breach.
        // - `Withdrawn` / `Slashed` / `Aborted`: terminal, reject all events.
        match self.state() {
            GraphState::AllNackd { .. } => {
                self.state = GraphState::Aborted {
                    claim_txid: self.state.claim_txid().unwrap_or(Txid::all_zeros()),
                    reason: AbortReason::PayoutConnectorSpent { spending_txid },
                };
                Ok(GSMOutput::new())
            }
            GraphState::Created { .. }
            | GraphState::GraphGenerated { .. }
            | GraphState::AdaptorsVerified { .. }
            | GraphState::NoncesCollected { .. }
            | GraphState::GraphSigned { .. }
            | GraphState::Assigned { .. }
            | GraphState::Fulfilled { .. } => Err(GSMError::invalid_event(
                self.state().clone(),
                event.into(),
                None,
            )),
            GraphState::BridgeProofTimedout { .. }
            | GraphState::Acked { .. }
            | GraphState::Withdrawn { .. }
            | GraphState::Slashed { .. }
            | GraphState::Aborted { .. } => Err(GSMError::rejected(
                self.state().clone(),
                event.into(),
                "connector spend has no actionable interpretation in this state",
            )),
            // Two-fact post-`Claimed` states are handled above.
            GraphState::Claimed { .. }
            | GraphState::Contested { .. }
            | GraphState::BridgeProofPosted { .. }
            | GraphState::CounterProofPosted { .. } => unreachable!(
                "two-fact post-Claimed states are handled by set_payout_connector_spent above"
            ),
        }
    }
}

/// Returns whether `txid` is the legitimate payout transaction for this state.
fn is_payout_tx(state: &GraphState, txid: &Txid) -> bool {
    match state {
        GraphState::Claimed { graph_summary, .. } => {
            *txid == graph_summary.uncontested_payout || *txid == graph_summary.contested_payout
        }
        GraphState::Contested { graph_summary, .. }
        | GraphState::BridgeProofPosted { graph_summary, .. }
        | GraphState::CounterProofPosted { graph_summary, .. } => {
            *txid == graph_summary.contested_payout
        }
        GraphState::AllNackd {
            expected_payout_txid,
            ..
        } => *txid == *expected_payout_txid,
        _ => false,
    }
}
