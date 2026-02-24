//! Classification of off-chain events (P2P gossip, requests, assignments) into state-machine-
//! specific events.

use bitcoin_bosd::Descriptor;
use musig2::{PartialSignature, PubNonce};
use strata_asm_proto_bridge_v1::AssignmentEntry;
use strata_bridge_p2p_types2::{MuSig2Nonce, MuSig2Partial, UnsignedGossipsubMsg};
use strata_bridge_sm::{
    deposit::{events as DepositEvents, events::DepositEvent},
    graph::{events as GraphEvents, events::GraphEvent},
};
use tracing::warn;

use crate::{
    events_mux::UnifiedEvent,
    sm_registry::SMRegistry,
    sm_types::{OperatorKey, SMEvent, SMId},
};

/// Classifies a unified event into the typed event for a specific state machine.
///
/// Returns `None` if the event is not applicable to the given SM (e.g., wrong SM type, or the
/// event doesn't carry data for this SM's deposit/graph index).
pub(crate) fn classify(
    sm_id: &SMId,
    event: &UnifiedEvent,
    sm_registry: &SMRegistry,
) -> Option<SMEvent> {
    match event {
        UnifiedEvent::OuroborosMessage(msg) => {
            classify_unsigned_gossip(sm_registry, &OperatorKey::Pov, msg)
                .into_iter()
                .next()
        }

        UnifiedEvent::GossipMessage(gossipsub_msg) => classify_unsigned_gossip(
            sm_registry,
            &OperatorKey::Peer(&gossipsub_msg.key),
            &gossipsub_msg.unsigned,
        )
        .into_iter()
        .next(),

        // technically an on-chain event but classified here since it's emitted by the ASM and
        // consumed by the SMs without any direct on-chain interaction
        UnifiedEvent::Assignment(entries) => classify_assignment(sm_id, entries),

        UnifiedEvent::Block(_) | UnifiedEvent::Shutdown(_) => None,

        UnifiedEvent::OuroborosRequest(_) => unimplemented!("see STR-2329"),
        UnifiedEvent::ReqRespRequest { .. } => unimplemented!("see STR-2329"),
        UnifiedEvent::NagTick => unimplemented!("see STR-2329"),
        UnifiedEvent::RetryTick => unimplemented!("see STR-2329"),
    }
}

/// Classifies an [`UnsignedGossipsubMsg`] into state-machine-specific events.
///
/// Both the ouroboros (self-published) and gossip (peer-received) paths use this function,
/// differing only in how the operator is identified via [`OperatorKey`].
pub(crate) fn classify_unsigned_gossip(
    sm_registry: &SMRegistry,
    key: &OperatorKey<'_>,
    msg: &UnsignedGossipsubMsg,
) -> Vec<SMEvent> {
    match msg {
        UnsignedGossipsubMsg::PayoutDescriptorExchange {
            operator_desc,
            operator_idx,
            deposit_idx,
        } => {
            // FIXME: (@Rajil1213) this needs to validate the sender as well (see STR-2316)
            if let Ok(descriptor) = Descriptor::try_from(operator_desc.clone()) {
                vec![
                    DepositEvent::PayoutDescriptorReceived(
                        DepositEvents::PayoutDescriptorReceivedEvent {
                            operator_desc: descriptor,
                        },
                    )
                    .into(),
                ]
            } else {
                warn!(
                    %operator_desc, %operator_idx, %deposit_idx,
                    "Received invalid payout descriptor, ignoring"
                );
                vec![]
            }
        }

        UnsignedGossipsubMsg::Musig2NoncesExchange(musig2_nonce) => match musig2_nonce {
            MuSig2Nonce::Deposit { deposit_idx, nonce } => sm_registry
                .lookup_operator(&(*deposit_idx).into(), key)
                .into_iter()
                .filter_map(|op_idx| {
                    PubNonce::try_from(*nonce)
                        .inspect_err(|_| {
                            warn!(
                                %deposit_idx, %op_idx,
                                "Received invalid deposit nonce, discarding message"
                            )
                        })
                        .ok()
                        .map(|pubnonce| {
                            DepositEvent::NonceReceived(DepositEvents::NonceReceivedEvent {
                                nonce: pubnonce,
                                operator_idx: op_idx,
                            })
                            .into()
                        })
                })
                .collect(),

            MuSig2Nonce::Payout { deposit_idx, nonce } => sm_registry
                .lookup_operator(&(*deposit_idx).into(), key)
                .into_iter()
                .filter_map(|op_idx| {
                    PubNonce::try_from(*nonce)
                        .inspect_err(|_| {
                            warn!(
                                %deposit_idx, %op_idx,
                                "Received invalid payout nonce, discarding message"
                            )
                        })
                        .ok()
                        .map(|pubnonce| {
                            DepositEvent::PayoutNonceReceived(
                                DepositEvents::PayoutNonceReceivedEvent {
                                    payout_nonce: pubnonce,
                                    operator_idx: op_idx,
                                },
                            )
                            .into()
                        })
                })
                .collect(),

            MuSig2Nonce::Graph { graph_idx, nonces } => sm_registry
                .lookup_operator(&(*graph_idx).into(), key)
                .into_iter()
                .filter_map(|op_idx| {
                    nonces
                        .iter()
                        .map(|n| PubNonce::try_from(*n))
                        .collect::<Result<Vec<_>, _>>()
                        .inspect_err(|_| {
                            warn!(
                                %graph_idx, %op_idx,
                                "Received invalid pubnonce for graph, discarding message"
                            )
                        })
                        .ok()
                        .map(|pubnonces| {
                            GraphEvent::NoncesReceived(GraphEvents::GraphNoncesReceivedEvent {
                                pubnonces,
                                operator_idx: op_idx,
                            })
                            .into()
                        })
                })
                .collect(),
        },

        UnsignedGossipsubMsg::Musig2SignaturesExchange(musig2_partial) => {
            match musig2_partial {
                MuSig2Partial::Deposit {
                    deposit_idx,
                    partial,
                } => sm_registry
                    .lookup_operator(&(*deposit_idx).into(), key)
                    .into_iter()
                    .filter_map(|op_idx| {
                        PartialSignature::try_from(*partial)
                            .inspect_err(|_| {
                                warn!(
                                    %deposit_idx, %op_idx,
                                    "Received invalid deposit partial signature, discarding message"
                                )
                            })
                            .ok()
                            .map(|partial_sig| {
                                DepositEvent::PartialReceived(DepositEvents::PartialReceivedEvent {
                                    partial_sig,
                                    operator_idx: op_idx,
                                })
                                .into()
                            })
                    })
                    .collect(),

                MuSig2Partial::Payout {
                    deposit_idx,
                    partial,
                } => sm_registry
                    .lookup_operator(&(*deposit_idx).into(), key)
                    .into_iter()
                    .filter_map(|op_idx| {
                        PartialSignature::try_from(*partial)
                            .inspect_err(|_| {
                                warn!(
                                    %deposit_idx, %op_idx,
                                    "Received invalid payout partial signature, discarding message"
                                )
                            })
                            .ok()
                            .map(|partial_sig| {
                                DepositEvent::PayoutPartialReceived(
                                    DepositEvents::PayoutPartialReceivedEvent {
                                        partial_signature: partial_sig,
                                        operator_idx: op_idx,
                                    },
                                )
                                .into()
                            })
                    })
                    .collect(),

                MuSig2Partial::Graph {
                    graph_idx,
                    partials,
                } => sm_registry
                    .lookup_operator(&(*graph_idx).into(), key)
                    .into_iter()
                    .filter_map(|op_idx| {
                        partials.iter()
                        .map(|p| PartialSignature::try_from(*p))
                        .collect::<Result<Vec<_>, _>>()
                        .inspect_err(|_| warn!(
                            %graph_idx, %op_idx,
                            "Received invalid partial signature for graph, discarding message"
                        ))
                        .ok()
                        .map(|partial_signatures| GraphEvent::PartialsReceived(
                            GraphEvents::GraphPartialsReceivedEvent {
                                partial_signatures,
                                operator_idx: op_idx,
                            },
                        ).into())
                    })
                    .collect(),
            }
        }
    }
}

/// Classifies an assignment entry into the typed event for a specific SM.
///
/// Each assignment is relevant to both the deposit and graph SMs, but this function returns only
/// the event matching `sm_id`'s type, paired with the entry whose `deposit_idx` matches.
fn classify_assignment(sm_id: &SMId, entries: &[AssignmentEntry]) -> Option<SMEvent> {
    match sm_id {
        SMId::Deposit(deposit_idx) => entries.iter().find_map(|entry| {
            (entry.deposit_idx() == *deposit_idx).then(|| {
                DepositEvent::WithdrawalAssigned(DepositEvents::WithdrawalAssignedEvent {
                    assignee: entry.current_assignee(),
                    deadline: entry.fulfillment_deadline(),
                    recipient_desc: entry.withdrawal_command().destination().clone(),
                })
                .into()
            })
        }),
        SMId::Graph(graph_idx) => entries.iter().find_map(|entry| {
            (entry.deposit_idx() == graph_idx.deposit).then(|| {
                GraphEvent::WithdrawalAssigned(GraphEvents::WithdrawalAssignedEvent {
                    assignee: entry.current_assignee(),
                    deadline: entry.fulfillment_deadline(),
                    recipient_desc: entry.withdrawal_command().destination().clone(),
                })
                .into()
            })
        }),
    }
}

#[cfg(test)]
mod tests {
    use strata_bridge_primitives::types::GraphIdx;

    use super::*;
    use crate::testing::test_empty_registry;

    // ===== classify_assignment tests =====

    /// Helper: generate an `AssignmentEntry` using the arbitrary crate and return it alongside its
    /// observed `deposit_idx`.
    fn arb_entry() -> (AssignmentEntry, u32) {
        let mut arb = strata_bridge_test_utils::arbitrary_generator::ArbitraryGenerator::new();
        let entry: AssignmentEntry = arb.generate();
        let idx = entry.deposit_idx();
        (entry, idx)
    }

    #[test]
    fn classify_assignment_deposit_matching() {
        let (entry, dep_idx) = arb_entry();
        let sm_id = SMId::Deposit(dep_idx);

        let result = classify_assignment(&sm_id, &[entry]);
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), SMEvent::Deposit(_)));
    }

    #[test]
    fn classify_assignment_deposit_no_match() {
        let (entry, dep_idx) = arb_entry();
        // Use a different deposit index that won't match
        let sm_id = SMId::Deposit(dep_idx.wrapping_add(1));

        let result = classify_assignment(&sm_id, &[entry]);
        assert!(result.is_none());
    }

    #[test]
    fn classify_assignment_graph_matching() {
        let (entry, dep_idx) = arb_entry();
        let sm_id = SMId::Graph(GraphIdx {
            deposit: dep_idx,
            operator: 0,
        });

        let result = classify_assignment(&sm_id, &[entry]);
        assert!(result.is_some());
        assert!(matches!(result.unwrap(), SMEvent::Graph(_)));
    }

    #[test]
    fn classify_assignment_graph_no_match() {
        let (entry, dep_idx) = arb_entry();
        let sm_id = SMId::Graph(GraphIdx {
            deposit: dep_idx.wrapping_add(1),
            operator: 0,
        });

        let result = classify_assignment(&sm_id, &[entry]);
        assert!(result.is_none());
    }

    #[test]
    fn classify_assignment_correct_fields() {
        let (entry, dep_idx) = arb_entry();
        let expected_assignee = entry.current_assignee();
        let expected_deadline = entry.fulfillment_deadline();
        let expected_desc = entry.withdrawal_command().destination().clone();

        let sm_id = SMId::Deposit(dep_idx);
        let result = classify_assignment(&sm_id, &[entry]).unwrap();

        match result {
            SMEvent::Deposit(boxed) => match *boxed {
                DepositEvent::WithdrawalAssigned(ref evt) => {
                    assert_eq!(evt.assignee, expected_assignee);
                    assert_eq!(evt.deadline, expected_deadline);
                    assert_eq!(evt.recipient_desc, expected_desc);
                }
                other => panic!("expected WithdrawalAssigned, got {other}"),
            },
            _ => panic!("expected Deposit event"),
        }
    }

    // ===== classify() top-level routing tests =====

    #[test]
    fn classify_block_returns_none() {
        use bitcoin::hashes::Hash;

        let registry = test_empty_registry();
        let block_event = btc_tracker::event::BlockEvent {
            block: bitcoin::Block {
                header: bitcoin::block::Header {
                    version: bitcoin::block::Version::ONE,
                    prev_blockhash: bitcoin::BlockHash::all_zeros(),
                    merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                    time: 0,
                    bits: bitcoin::CompactTarget::from_consensus(0),
                    nonce: 0,
                },
                txdata: vec![],
            },
            status: btc_tracker::event::BlockStatus::Buried,
        };
        let event = UnifiedEvent::Block(block_event);
        let sm_id = SMId::Deposit(0);

        let result = classify(&sm_id, &event, &registry);
        assert!(result.is_none());
    }

    #[test]
    fn classify_shutdown_returns_none() {
        let registry = test_empty_registry();
        let (tx, _rx) = tokio::sync::oneshot::channel::<()>();
        let event = UnifiedEvent::Shutdown(tx);
        let sm_id = SMId::Deposit(0);

        let result = classify(&sm_id, &event, &registry);
        assert!(result.is_none());
    }
}
