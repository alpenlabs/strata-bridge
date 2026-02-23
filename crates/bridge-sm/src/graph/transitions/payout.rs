use crate::graph::{
    errors::{GSMError, GSMResult},
    events::PayoutConfirmedEvent,
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
            // TODO: STR-2196
            GraphState::BridgeProofPosted { .. } => {
                todo!()
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
}
