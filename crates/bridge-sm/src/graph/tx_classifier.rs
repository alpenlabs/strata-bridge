//! [`TxClassifier`] implementation for [`GraphSM`].

use bitcoin::{Transaction, script::Instruction};
use strata_bridge_primitives::types::BitcoinBlockHeight;
use zkaleido::{Proof, ProofReceipt, PublicValues};

use crate::{
    graph::{
        events::{
            BridgeProofConfirmedEvent, BridgeProofTimeoutConfirmedEvent, ClaimConfirmedEvent,
            ContestConfirmedEvent, CounterProofAckConfirmedEvent, CounterProofConfirmedEvent,
            CounterProofNackConfirmedEvent, FulfillmentConfirmedEvent, GraphEvent,
            PayoutConfirmedEvent, PayoutConnectorSpentEvent, SlashConfirmedEvent,
        },
        machine::GraphSM,
        state::GraphState,
    },
    tx_classifier::{
        TxClassifier, is_bridge_proof_tx, is_counterproof_ack_txid, is_counterproof_nack_tx,
        is_counterproof_txid, is_fulfillment, is_payout_connector_spent,
    },
};

impl TxClassifier for GraphSM {
    fn classify_tx(
        &self,
        config: &Self::Config,
        tx: &Transaction,
        height: BitcoinBlockHeight,
    ) -> Option<Self::Event> {
        let txid = tx.compute_txid();

        match self.state() {
            GraphState::Created { .. } => None, // does not expect any txs
            //
            // might see claim if an operator is malicious
            GraphState::GraphGenerated { graph_summary, .. }
            | GraphState::AdaptorsVerified { graph_summary, .. }
            | GraphState::NoncesCollected { graph_summary, .. }
            | GraphState::GraphSigned { graph_summary, .. }
                if txid == graph_summary.claim =>
            {
                Some(GraphEvent::ClaimConfirmed(ClaimConfirmedEvent {
                    claim_txid: txid,
                    claim_block_height: height,
                }))
            }

            // expects a fulfillment transaction
            GraphState::Assigned {
                recipient_desc,
                graph_summary,
                ..
            } => {
                if is_fulfillment(
                    config.game_graph_params.magic_bytes,
                    self.context.deposit_idx(),
                    config.game_graph_params.deposit_amount,
                    recipient_desc,
                    tx,
                ) {
                    Some(GraphEvent::FulfillmentConfirmed(
                        FulfillmentConfirmedEvent {
                            fulfillment_txid: txid,
                            fulfillment_block_height: height,
                        },
                    ))
                } else if txid == graph_summary.claim {
                    // might see claim if an operator is faulty
                    Some(GraphEvent::ClaimConfirmed(ClaimConfirmedEvent {
                        claim_txid: txid,
                        claim_block_height: height,
                    }))
                } else {
                    None
                }
            }

            // expects a claim
            // NOTE: (@Rajil1213) we're deliberately not accepting a cooperative payout here because
            // that is tracked in the `DepositSM`. Once that happens, we can safely remove all
            // associated graphs. The alternative is to account for cooperative payouts in every
            // state after this state which is cumbersome.
            GraphState::Fulfilled { graph_summary, .. } => {
                if txid == graph_summary.claim {
                    Some(GraphEvent::ClaimConfirmed(ClaimConfirmedEvent {
                        claim_txid: txid,
                        claim_block_height: height,
                    }))
                } else {
                    None
                }
            }

            // expects a contest or an uncontested payout or payout burn
            GraphState::Claimed { graph_summary, .. } => {
                if txid == graph_summary.contest {
                    Some(GraphEvent::ContestConfirmed(ContestConfirmedEvent {
                        contest_txid: txid,
                        contest_block_height: height,
                    }))
                } else if txid == graph_summary.uncontested_payout {
                    Some(GraphEvent::PayoutConfirmed(PayoutConfirmedEvent {
                        payout_txid: txid,
                    }))
                } else if is_payout_connector_spent(&graph_summary.claim, tx) {
                    Some(GraphEvent::PayoutConnectorSpent(
                        PayoutConnectorSpentEvent {
                            spending_txid: txid,
                        },
                    ))
                } else {
                    None
                }
            }

            // expects a bridge proof, a (faulty) counterproof or a bridge proof timeout or a payout
            // burn
            GraphState::Contested { graph_summary, .. } => {
                if is_bridge_proof_tx(graph_summary.contest, tx) {
                    let mut proof_and_public_values = vec![];
                    tx.output.iter().for_each(|output| {
                        if output.script_pubkey.is_op_return() {
                            for instr in output.script_pubkey.instructions() {
                                if let Ok(Instruction::PushBytes(bytes)) = instr {
                                    proof_and_public_values.extend(bytes.as_bytes().to_vec());
                                }
                            }
                        }
                    });

                    // TODO: (@Rajil1213) we need to define the binary encoding of proof and public
                    // values. Use that to parse the `proof_and_public_values` into a `ProofReceipt`
                    // and a struct of public values required for the state transition.
                    let proof_receipt = ProofReceipt::new(
                        Proof::new(proof_and_public_values.clone()),
                        PublicValues::new(vec![]),
                    );

                    Some(GraphEvent::BridgeProofConfirmed(
                        BridgeProofConfirmedEvent {
                            bridge_proof_txid: txid,
                            bridge_proof_block_height: height,

                            proof: proof_receipt,
                        },
                    ))
                } else if is_counterproof_txid(graph_summary, &txid) {
                    Some(GraphEvent::CounterProofConfirmed(
                        CounterProofConfirmedEvent {
                            counterproof_txid: txid,
                            counterproof_block_height: height,
                        },
                    ))
                } else if is_payout_connector_spent(&graph_summary.claim, tx) {
                    Some(GraphEvent::PayoutConnectorSpent(
                        PayoutConnectorSpentEvent {
                            spending_txid: txid,
                        },
                    ))
                } else {
                    None
                }
            }

            // expects a counterproof or a contested payout or a payout burn
            GraphState::BridgeProofPosted { graph_summary, .. } => {
                if is_counterproof_txid(graph_summary, &txid) {
                    Some(GraphEvent::CounterProofConfirmed(
                        CounterProofConfirmedEvent {
                            counterproof_txid: txid,
                            counterproof_block_height: height,
                        },
                    ))
                } else if txid == graph_summary.contested_payout {
                    Some(GraphEvent::PayoutConfirmed(PayoutConfirmedEvent {
                        payout_txid: txid,
                    }))
                } else if is_payout_connector_spent(&graph_summary.claim, tx) {
                    Some(GraphEvent::PayoutConnectorSpent(
                        PayoutConnectorSpentEvent {
                            spending_txid: txid,
                        },
                    ))
                } else {
                    None
                }
            }

            // expects a slash or a payout burn
            GraphState::BridgeProofTimedout { graph_summary, .. } => {
                if graph_summary.bridge_proof_timeout == txid {
                    Some(GraphEvent::BridgeProofTimeoutConfirmed(
                        BridgeProofTimeoutConfirmedEvent {
                            bridge_proof_timeout_txid: txid,
                            bridge_proof_timeout_block_height: height,
                        },
                    ))
                } else if is_payout_connector_spent(&graph_summary.claim, tx) {
                    Some(GraphEvent::PayoutConnectorSpent(
                        PayoutConnectorSpentEvent {
                            spending_txid: txid,
                        },
                    ))
                } else {
                    None
                }
            }

            // expects a counterproof ACK or NACK or payout burn
            GraphState::CounterProofPosted { graph_summary, .. } => {
                if is_counterproof_ack_txid(graph_summary, &txid) {
                    Some(GraphEvent::CounterProofAckConfirmed(
                        CounterProofAckConfirmedEvent {
                            counterproof_ack_txid: txid,
                            counterproof_ack_block_height: height,
                        },
                    ))
                } else if is_payout_connector_spent(&graph_summary.claim, tx) {
                    Some(GraphEvent::PayoutConnectorSpent(
                        PayoutConnectorSpentEvent {
                            spending_txid: txid,
                        },
                    ))
                } else {
                    is_counterproof_nack_tx(
                        graph_summary,
                        self.context.operator_table.pov_idx(),
                        tx,
                    )
                    .map(|nacker_idx| {
                        GraphEvent::CounterProofNackConfirmed(CounterProofNackConfirmedEvent {
                            counterproof_nack_txid: txid,
                            nacker_idx,
                        })
                    })
                }
            }

            // expects a contested payout or a slash if there is delay in posting payout
            GraphState::AllNackd {
                expected_payout_txid,
                possible_slash_txid,
                ..
            } => {
                if txid == *expected_payout_txid {
                    Some(GraphEvent::PayoutConfirmed(PayoutConfirmedEvent {
                        payout_txid: *expected_payout_txid,
                    }))
                } else if txid == *possible_slash_txid {
                    Some(GraphEvent::SlashConfirmed(SlashConfirmedEvent {
                        slash_txid: txid,
                    }))
                } else {
                    None
                }
            }

            // expects a slash
            GraphState::Acked {
                expected_slash_txid,
                ..
            } => {
                if txid == *expected_slash_txid {
                    Some(GraphEvent::SlashConfirmed(SlashConfirmedEvent {
                        slash_txid: txid,
                    }))
                } else {
                    None
                }
            }

            // terminal states expect no txs
            GraphState::Withdrawn { .. } => None,
            GraphState::Slashed { .. } => None,
            GraphState::Aborted { .. } => None,

            _ => None, // other states do not expect any txs
        }
    }
}
