use tracing::{info, warn};

use crate::graph::{
    errors::{GSMError, GSMResult},
    events::{PayoutConfirmedEvent, PayoutConnectorSpentEvent},
    machine::{GSMOutput, GraphSM},
    state::GraphState,
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
                    payout_txid: payout_event.payout_txid,
                };

                Ok(GSMOutput::new())
            }
            GraphState::AllNackd {
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

    /// Processes the event where the payout connector has been spent by an
    /// unexpected transaction.
    ///
    /// Note: The ordering of payout checks vs payout connector spent checks is
    /// enforced by the tx_classifier, which checks for valid payout transactions
    /// before checking for payout connector spend.
    pub(crate) fn process_payout_connector_spent(
        &mut self,
        event: PayoutConnectorSpentEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state() {
            // States that can observe payout connector spend
            GraphState::Claimed { .. }
            | GraphState::Contested { .. }
            | GraphState::BridgeProofPosted { .. }
            | GraphState::BridgeProofTimedout { .. }
            | GraphState::CounterProofPosted { .. } => {
                self.state = GraphState::Aborted {
                    payout_connector_spend_txid: event.spending_txid,
                    reason: "Payout connector spent".to_string(),
                };

                Ok(GSMOutput::new())
            }
            // Already aborted - duplicate event
            GraphState::Aborted { .. } => {
                Err(GSMError::duplicate(self.state().clone(), event.into()))
            }
            // Invalid state for this event
            _ => Err(GSMError::invalid_event(
                self.state().clone(),
                event.into(),
                None,
            )),
        }
    }
}
