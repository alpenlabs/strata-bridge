use crate::graph::{
    errors::{GSMError, GSMResult},
    events::BridgeProofTimeoutConfirmedEvent,
    machine::{GSMOutput, GraphSM},
    state::GraphState,
};

impl GraphSM {
    pub(crate) fn process_bridge_proof_timeout(
        &mut self,
        event: BridgeProofTimeoutConfirmedEvent,
    ) -> GSMResult<GSMOutput> {
        match self.state.clone() {
            GraphState::Contested {
                last_block_height,
                graph_data,
                graph_summary,
                signatures,
                fulfillment_txid: _,
                fulfillment_block_height: _,
                contest_block_height,
            } => {
                if event.bridge_proof_timeout_block_height < last_block_height {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "event has old block height",
                    ));
                }
                if event.bridge_proof_timeout_txid != graph_summary.bridge_proof_timeout {
                    return Err(GSMError::rejected(
                        self.state.clone(),
                        event.into(),
                        "invalid bridge proof txid",
                    ));
                }

                self.state = GraphState::BridgeProofTimedout {
                    last_block_height: event.bridge_proof_timeout_block_height,
                    graph_data,
                    signatures,
                    contest_block_height,
                    expected_slash_txid: graph_summary.slash,
                    claim_txid: graph_summary.claim,
                    graph_summary,
                };

                Ok(GSMOutput::default())
            }
            state @ GraphState::BridgeProofTimedout { .. } => {
                Err(GSMError::duplicate(state, event.into()))
            }
            state => Err(GSMError::invalid_event(state, event.into(), None)),
        }
    }
}
