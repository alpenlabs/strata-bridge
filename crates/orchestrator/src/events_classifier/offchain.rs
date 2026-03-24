//! Classification of off-chain events (P2P gossip, requests, assignments) into state-machine-
//! specific events.

use bitcoin_bosd::Descriptor;
use musig2::{PartialSignature, PubNonce};
use strata_asm_proto_bridge_v1::AssignmentEntry;
use strata_bridge_p2p_types::{
    MuSig2Nonce, MuSig2Partial, NagRequestPayload, UnsignedGossipsubMsg,
};
use strata_bridge_sm::{
    deposit::events::{self as DepositEvents, DepositEvent, RetryTickEvent},
    graph::events::{self as GraphEvents, GraphEvent},
};
use tracing::{debug, info, warn};

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
            classify_unsigned_gossip(sm_registry, &OperatorKey::Pov, &msg.publish)
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

        UnifiedEvent::Block(_) | UnifiedEvent::Shutdown => None,

        UnifiedEvent::NagTick => classify_nag_tick(sm_id, sm_registry),
        UnifiedEvent::RetryTick => classify_retry_tick(sm_id, sm_registry),
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
        UnsignedGossipsubMsg::GraphDataExchange {
            graph_idx,
            claim_input,
        } => {
            let Some(sender_idx) = sm_registry.lookup_operator(&SMId::Graph(*graph_idx), key)
            else {
                warn!(
                    %graph_idx,
                    "Received graph data from unknown sender, ignoring"
                );
                return vec![];
            };

            if sender_idx != graph_idx.operator {
                warn!(
                    %graph_idx, %sender_idx,
                    "Received graph data with sender/operator mismatch, ignoring"
                );
                return vec![];
            }

            vec![
                GraphEvent::GraphDataProduced(GraphEvents::GraphDataGeneratedEvent {
                    graph_idx: *graph_idx,
                    claim_funds: claim_input.inner(),
                })
                .into(),
            ]
        }
        UnsignedGossipsubMsg::PayoutDescriptorExchange {
            operator_desc,
            operator_idx,
            deposit_idx,
        } => {
            let sm_id = SMId::Deposit(*deposit_idx);
            let Some(sender_idx) = sm_registry.lookup_operator(&sm_id, key) else {
                warn!(
                    %deposit_idx, %operator_idx,
                    "Received payout descriptor from unknown sender, ignoring"
                );
                return vec![];
            };

            if sender_idx != *operator_idx {
                warn!(
                    %deposit_idx, claimed_operator_idx=%operator_idx, resolved_operator_idx=%sender_idx,
                    "Received payout descriptor with sender/operator mismatch, ignoring"
                );
                return vec![];
            }

            if let Ok(descriptor) = Descriptor::try_from(operator_desc.clone()) {
                vec![
                    DepositEvent::PayoutDescriptorReceived(
                        DepositEvents::PayoutDescriptorReceivedEvent {
                            operator_idx: *operator_idx,
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

        UnsignedGossipsubMsg::NagRequestExchange(nag_request) => {
            let sm_id = match &nag_request.payload {
                NagRequestPayload::DepositNonce { deposit_idx }
                | NagRequestPayload::DepositPartial { deposit_idx }
                | NagRequestPayload::PayoutNonce { deposit_idx }
                | NagRequestPayload::PayoutPartial { deposit_idx } => SMId::Deposit(*deposit_idx),
                NagRequestPayload::GraphData { graph_idx }
                | NagRequestPayload::GraphNonces { graph_idx }
                | NagRequestPayload::GraphPartials { graph_idx } => SMId::Graph(*graph_idx),
            };

            info!(
                target_sm = %sm_id,
                sender = ?key,
                recipient = ?nag_request.recipient,
                payload = ?nag_request.payload,
                "classifying incoming nag request"
            );

            // Router guarantees target SM exists for routed events.
            let pov_p2p_key = match sm_id {
                SMId::Deposit(deposit_idx) => sm_registry
                    .get_deposit(&deposit_idx)
                    .map(|sm| sm.context().operator_table().pov_p2p_key().clone())
                    .expect("router should route nags only to existing deposit SMs"),
                SMId::Graph(graph_idx) => sm_registry
                    .get_graph(&graph_idx)
                    .map(|sm| sm.context().operator_table().pov_p2p_key().clone())
                    .expect("router should route nags only to existing graph SMs"),
            };

            // Check recipient matches POV
            if nag_request.recipient != pov_p2p_key {
                debug!(
                    target_sm = %sm_id,
                    recipient = ?nag_request.recipient,
                    pov = ?pov_p2p_key,
                    payload = ?nag_request.payload,
                    "dropping nag: recipient does not match POV operator"
                );
                return vec![];
            }

            // Resolve sender to operator_idx
            let Some(sender_operator_idx) = sm_registry.lookup_operator(&sm_id, key) else {
                warn!(
                    target_sm = %sm_id,
                    sender = ?key,
                    payload = ?nag_request.payload,
                    "dropping nag: sender is not in operator table for target state machine"
                );
                return vec![];
            };

            info!(
                target_sm = %sm_id,
                sender_operator_idx,
                payload = ?nag_request.payload,
                "accepted nag request and mapping to state machine event"
            );

            let event = match &nag_request.payload {
                NagRequestPayload::DepositNonce { .. }
                | NagRequestPayload::DepositPartial { .. }
                | NagRequestPayload::PayoutNonce { .. }
                | NagRequestPayload::PayoutPartial { .. } => {
                    DepositEvent::NagReceived(DepositEvents::NagReceivedEvent {
                        payload: nag_request.payload.clone(),
                        sender_operator_idx,
                    })
                    .into()
                }
                NagRequestPayload::GraphData { .. }
                | NagRequestPayload::GraphNonces { .. }
                | NagRequestPayload::GraphPartials { .. } => {
                    GraphEvent::NagReceived(GraphEvents::NagReceivedEvent {
                        payload: nag_request.payload.clone(),
                        sender_operator_idx,
                    })
                    .into()
                }
            };

            vec![event]
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
                    deadline: entry.fulfillment_deadline().into(),
                    recipient_desc: entry.withdrawal_command().destination().clone(),
                })
                .into()
            })
        }),
        SMId::Graph(graph_idx) => entries.iter().find_map(|entry| {
            (entry.deposit_idx() == graph_idx.deposit).then(|| {
                GraphEvent::WithdrawalAssigned(GraphEvents::WithdrawalAssignedEvent {
                    assignee: entry.current_assignee(),
                    deadline: entry.fulfillment_deadline().into(),
                    recipient_desc: entry.withdrawal_command().destination().clone(),
                })
                .into()
            })
        }),
    }
}

fn classify_nag_tick(sm_id: &SMId, sm_registry: &SMRegistry) -> Option<SMEvent> {
    match sm_id {
        SMId::Deposit(deposit_idx) => sm_registry
            .get_deposit(deposit_idx)
            .map(|_| DepositEvent::NagTick(DepositEvents::NagTickEvent).into()),
        SMId::Graph(_graph_idx) => sm_registry
            .get_graph(_graph_idx)
            .map(|_| GraphEvent::NagTick(GraphEvents::NagTickEvent).into()),
    }
}

fn classify_retry_tick(sm_id: &SMId, sm_registry: &SMRegistry) -> Option<SMEvent> {
    match sm_id {
        SMId::Deposit(deposit_idx) => sm_registry
            .get_deposit(deposit_idx)
            .map(|_| DepositEvent::RetryTick(RetryTickEvent).into()),
        SMId::Graph(_graph_idx) => sm_registry
            .get_graph(_graph_idx)
            .map(|_| GraphEvent::RetryTick(GraphEvents::RetryTickEvent).into()),
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{OutPoint, Txid, hashes::Hash};
    use strata_bridge_p2p_types::{
        ClaimInput, GossipsubMsg, PayoutDescriptor, UnsignedGossipsubMsg,
    };
    use strata_bridge_primitives::types::{
        BitcoinBlockHeight, DepositIdx, GraphIdx, OperatorIdx, P2POperatorPubKey,
    };

    use super::*;
    use crate::testing::{
        insert_deposit_with_graphs, random_p2tr_desc, test_empty_registry, test_populated_registry,
    };

    // ===== classify_assignment tests =====

    /// Helper: generate an `AssignmentEntry` using the arbitrary crate and return it alongside its
    /// observed `deposit_idx`.
    fn arb_entry() -> (AssignmentEntry, u32) {
        let mut arb = strata_bridge_test_utils::arbitrary_generator::ArbitraryGenerator::new();
        let entry: AssignmentEntry = arb.generate();
        let idx = entry.deposit_idx();
        (entry, idx)
    }

    fn payout_descriptor_msg(
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
    ) -> UnsignedGossipsubMsg {
        UnsignedGossipsubMsg::PayoutDescriptorExchange {
            deposit_idx,
            operator_idx,
            operator_desc: PayoutDescriptor::from(random_p2tr_desc()),
        }
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
        let expected_deadline: BitcoinBlockHeight = entry.fulfillment_deadline().into();
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
        let event = UnifiedEvent::Shutdown;
        let sm_id = SMId::Deposit(0);

        let result = classify(&sm_id, &event, &registry);
        assert!(result.is_none());
    }

    #[test]
    fn classify_nag_tick_existing_deposit_returns_nag_tick_event() {
        let mut registry = test_empty_registry();
        let deposit_idx = 42;
        insert_deposit_with_graphs(&mut registry, deposit_idx);

        let sm_id = SMId::Deposit(deposit_idx);
        let event = UnifiedEvent::NagTick;

        let result = classify(&sm_id, &event, &registry);
        match result {
            Some(SMEvent::Deposit(event)) => assert!(matches!(*event, DepositEvent::NagTick(_))),
            other => panic!("expected Deposit::NagTick, got {other:?}"),
        }
    }

    #[test]
    fn classify_nag_tick_missing_deposit_returns_none() {
        let registry = test_empty_registry();
        let sm_id = SMId::Deposit(999);
        let event = UnifiedEvent::NagTick;

        let result = classify(&sm_id, &event, &registry);
        assert!(result.is_none());
    }

    #[test]
    fn classify_nag_tick_existing_graph_returns_nag_tick_event() {
        let mut registry = test_empty_registry();
        let deposit_idx = 42;
        insert_deposit_with_graphs(&mut registry, deposit_idx);

        let sm_id = SMId::Graph(GraphIdx {
            deposit: deposit_idx,
            operator: 0,
        });
        let event = UnifiedEvent::NagTick;

        let result = classify(&sm_id, &event, &registry);
        match result {
            Some(SMEvent::Graph(event)) => assert!(matches!(*event, GraphEvent::NagTick(_))),
            other => panic!("expected Deposit::NagTick, got {other:?}"),
        }
    }

    #[test]
    fn classify_nag_tick_missing_graph_returns_none() {
        let mut registry = test_empty_registry();
        const DEPOSIT_IDX: DepositIdx = 42;
        insert_deposit_with_graphs(&mut registry, DEPOSIT_IDX);

        const MISSING_DEPOSIT_IDX: DepositIdx = 999;
        const {
            assert!(
                DEPOSIT_IDX != MISSING_DEPOSIT_IDX,
                "test setup error: missing deposit should not exist in registry"
            )
        };

        let sm_id = SMId::Graph(GraphIdx {
            deposit: MISSING_DEPOSIT_IDX,
            operator: 0,
        });
        let event = UnifiedEvent::NagTick;

        let result = classify(&sm_id, &event, &registry);
        assert!(result.is_none());
    }

    #[test]
    fn classify_retry_tick_existing_deposit_returns_retry_tick_event() {
        let mut registry = test_empty_registry();
        let deposit_idx = 42;
        insert_deposit_with_graphs(&mut registry, deposit_idx);

        let sm_id = SMId::Deposit(deposit_idx);
        let event = UnifiedEvent::RetryTick;

        let result = classify(&sm_id, &event, &registry);
        match result {
            Some(SMEvent::Deposit(event)) => {
                assert!(matches!(*event, DepositEvent::RetryTick(_)));
            }
            other => panic!("expected Deposit::RetryTick, got {other:?}"),
        }
    }

    #[test]
    fn classify_retry_tick_missing_deposit_returns_none() {
        let registry = test_empty_registry();
        let sm_id = SMId::Deposit(999);
        let event = UnifiedEvent::RetryTick;

        let result = classify(&sm_id, &event, &registry);
        assert!(result.is_none());
    }

    #[test]
    fn classify_retry_tick_existing_graph_returns_retry_tick_event() {
        let mut registry = test_empty_registry();
        let deposit_idx = 42;
        insert_deposit_with_graphs(&mut registry, deposit_idx);

        let sm_id = SMId::Graph(GraphIdx {
            deposit: deposit_idx,
            operator: 0,
        });
        let event = UnifiedEvent::RetryTick;

        let result = classify(&sm_id, &event, &registry);
        match result {
            Some(SMEvent::Graph(event)) => {
                assert!(matches!(*event, GraphEvent::RetryTick(_)));
            }
            other => panic!("expected Deposit::RetryTick, got {other:?}"),
        }
    }

    #[test]
    fn classify_retry_tick_missing_graph_returns_none() {
        let registry = test_empty_registry();
        let sm_id = SMId::Graph(GraphIdx {
            deposit: 999,
            operator: 0,
        });
        let event = UnifiedEvent::RetryTick;

        let result = classify(&sm_id, &event, &registry);
        assert!(result.is_none());
    }

    // ===== classify_unsigned_gossip() tests for PayoutDescriptorExchange =====

    #[test]
    fn classify_payout_descriptor_rejects_unknown_sender() {
        let registry = test_populated_registry(1);
        let unknown_key = P2POperatorPubKey::from(vec![0xAA; 32]);
        let msg = payout_descriptor_msg(0, 0);

        let events = classify_unsigned_gossip(&registry, &OperatorKey::Peer(&unknown_key), &msg);
        assert!(
            events.is_empty(),
            "should reject payout descriptor from unknown sender"
        );
    }

    #[test]
    fn classify_payout_descriptor_rejects_sender_idx_mismatch() {
        let registry = test_populated_registry(1);

        const OPERATOR_IN_PAYLOAD: OperatorIdx = 1;
        const SENDER_IDX_IN_MSG: OperatorIdx = 2;
        const {
            assert!(
                OPERATOR_IN_PAYLOAD != SENDER_IDX_IN_MSG,
                "test setup requires sender idx mismatch"
            )
        };

        let sender_key: P2POperatorPubKey = registry
            .get_deposit(&0)
            .expect("deposit exists")
            .context()
            .operator_table()
            .idx_to_p2p_key(&OPERATOR_IN_PAYLOAD)
            .expect("operator exists")
            .clone();
        let msg = payout_descriptor_msg(0, SENDER_IDX_IN_MSG);

        let events = classify_unsigned_gossip(&registry, &OperatorKey::Peer(&sender_key), &msg);
        assert!(
            events.is_empty(),
            "should reject payout descriptor with sender/operator mismatch"
        );
    }

    #[test]
    fn classify_payout_descriptor_accepts_matching_sender_and_idx() {
        let registry = test_populated_registry(1);
        const OPERATOR_IDX: OperatorIdx = 1;
        let sender_key: P2POperatorPubKey = registry
            .get_deposit(&0)
            .expect("deposit exists")
            .context()
            .operator_table()
            .idx_to_p2p_key(&OPERATOR_IDX)
            .expect("operator exists")
            .clone();
        let unsigned = payout_descriptor_msg(0, OPERATOR_IDX);
        let event = UnifiedEvent::GossipMessage(GossipsubMsg {
            signature: vec![],
            key: sender_key,
            unsigned,
        });

        let result = classify(&SMId::Deposit(0), &event, &registry);
        assert!(matches!(
            result,
            Some(SMEvent::Deposit(event))
                if matches!(*event, DepositEvent::PayoutDescriptorReceived(_))
        ));
    }

    // ===== classify_unsigned_gossip() tests for GraphDataExchange =====

    fn graph_data_msg(graph_idx: GraphIdx) -> UnsignedGossipsubMsg {
        UnsignedGossipsubMsg::GraphDataExchange {
            graph_idx,
            claim_input: ClaimInput::from(OutPoint::new(Txid::all_zeros(), 0)),
        }
    }

    #[test]
    fn classify_graph_data_rejects_unknown_sender() {
        let registry = test_populated_registry(1);
        let unknown_key = P2POperatorPubKey::from(vec![0xAA; 32]);
        let graph_idx = GraphIdx {
            deposit: 0,
            operator: 0,
        };
        let msg = graph_data_msg(graph_idx);

        let events = classify_unsigned_gossip(&registry, &OperatorKey::Peer(&unknown_key), &msg);
        assert!(
            events.is_empty(),
            "should reject graph data from unknown sender"
        );
    }

    #[test]
    fn classify_graph_data_rejects_sender_operator_mismatch() {
        let registry = test_populated_registry(1);

        // The graph claims operator 0 produced the data, but the actual sender resolves to
        // operator 1. Without the sender-identity check this would be accepted.
        const CLAIMED_OPERATOR: OperatorIdx = 0;
        const ACTUAL_SENDER: OperatorIdx = 1;
        const {
            assert!(
                CLAIMED_OPERATOR != ACTUAL_SENDER,
                "test setup requires sender/operator mismatch"
            )
        };

        let sender_key: P2POperatorPubKey = registry
            .get_deposit(&0)
            .expect("deposit exists")
            .context()
            .operator_table()
            .idx_to_p2p_key(&ACTUAL_SENDER)
            .expect("operator exists")
            .clone();

        let graph_idx = GraphIdx {
            deposit: 0,
            operator: CLAIMED_OPERATOR,
        };
        let msg = graph_data_msg(graph_idx);

        let events = classify_unsigned_gossip(&registry, &OperatorKey::Peer(&sender_key), &msg);
        assert!(
            events.is_empty(),
            "should reject graph data with sender/operator mismatch"
        );
    }

    #[test]
    fn classify_graph_data_accepts_matching_sender() {
        let registry = test_populated_registry(1);
        const OPERATOR_IDX: OperatorIdx = 1;

        let sender_key: P2POperatorPubKey = registry
            .get_deposit(&0)
            .expect("deposit exists")
            .context()
            .operator_table()
            .idx_to_p2p_key(&OPERATOR_IDX)
            .expect("operator exists")
            .clone();

        let graph_idx = GraphIdx {
            deposit: 0,
            operator: OPERATOR_IDX,
        };
        let msg = graph_data_msg(graph_idx);

        let events = classify_unsigned_gossip(&registry, &OperatorKey::Peer(&sender_key), &msg);
        assert_eq!(
            events.len(),
            1,
            "should accept graph data from matching sender"
        );
        assert!(
            matches!(events[0], SMEvent::Graph(ref e) if matches!(**e, GraphEvent::GraphDataProduced(_))),
            "should produce GraphDataProduced event"
        );
    }

    // ===== classify_nag_request tests =====
    mod nag_request_tests {
        use strata_bridge_p2p_types::{GraphIdx, NagRequest, NagRequestPayload};

        use super::*;
        use crate::testing::{
            N_TEST_OPERATORS, TEST_NONPOV, TEST_POV_IDX, insert_deposit_with_graphs,
            test_operator_table,
        };

        #[test]
        fn classify_nag_request_addressed_to_pov_creates_event() {
            let mut registry = test_empty_registry();
            let deposit_idx = 42u32;
            insert_deposit_with_graphs(&mut registry, deposit_idx);

            // Get the POV P2P key from the operator table
            let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
            let pov_p2p_key: P2POperatorPubKey = operator_table.pov_p2p_key().clone();

            // Get a non-POV operator's key as the sender
            let sender_idx = TEST_NONPOV; // Non-POV operator
            let sender_p2p_key = operator_table.idx_to_p2p_key(&sender_idx).unwrap().clone();

            let nag_request = NagRequest {
                recipient: pov_p2p_key,
                payload: NagRequestPayload::DepositNonce { deposit_idx },
            };

            let msg = UnsignedGossipsubMsg::NagRequestExchange(nag_request);
            let result =
                classify_unsigned_gossip(&registry, &OperatorKey::Peer(&sender_p2p_key), &msg);

            assert_eq!(result.len(), 1, "Should create exactly one event");
            match &result[0] {
                SMEvent::Deposit(boxed) => match boxed.as_ref() {
                    DepositEvent::NagReceived(evt) => {
                        assert!(matches!(
                            evt.payload,
                            NagRequestPayload::DepositNonce { .. }
                        ));
                        assert_eq!(evt.sender_operator_idx, sender_idx);
                    }
                    other => panic!("Expected NagReceived, got {other}"),
                },
                _ => panic!("Expected Deposit event"),
            }
        }

        #[test]
        fn classify_nag_request_not_addressed_to_pov_drops() {
            let mut registry = test_empty_registry();
            let deposit_idx = 42u32;
            insert_deposit_with_graphs(&mut registry, deposit_idx);

            // Create a recipient that is NOT the POV (use a different operator's key)
            let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
            let non_pov_idx = TEST_NONPOV;
            let non_pov_p2p_key: P2POperatorPubKey =
                operator_table.idx_to_p2p_key(&non_pov_idx).unwrap().clone();

            let sender_idx = TEST_POV_IDX;
            let sender_p2p_key = operator_table.idx_to_p2p_key(&sender_idx).unwrap().clone();

            let nag_request = NagRequest {
                recipient: non_pov_p2p_key, // Not addressed to POV
                payload: NagRequestPayload::DepositNonce { deposit_idx },
            };

            let msg = UnsignedGossipsubMsg::NagRequestExchange(nag_request);
            let result =
                classify_unsigned_gossip(&registry, &OperatorKey::Peer(&sender_p2p_key), &msg);

            assert!(result.is_empty(), "Should drop nag not addressed to us");
        }

        #[test]
        fn classify_nag_request_unknown_sender_drops() {
            let mut registry = test_empty_registry();
            let deposit_idx = 42u32;
            insert_deposit_with_graphs(&mut registry, deposit_idx);

            // Get the POV P2P key
            let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
            let pov_p2p_key: P2POperatorPubKey = operator_table.pov_p2p_key().clone();

            // Create an unknown sender key (not in operator table)
            let unknown_sender_key: P2POperatorPubKey = vec![0xffu8; 32].into();

            let nag_request = NagRequest {
                recipient: pov_p2p_key,
                payload: NagRequestPayload::DepositNonce { deposit_idx },
            };

            let msg = UnsignedGossipsubMsg::NagRequestExchange(nag_request);
            let result =
                classify_unsigned_gossip(&registry, &OperatorKey::Peer(&unknown_sender_key), &msg);

            assert!(result.is_empty(), "Should drop nag from unknown sender");
        }

        #[test]
        fn classify_graph_nag_request_addressed_to_pov_creates_graph_event() {
            let mut registry = test_empty_registry();
            let deposit_idx = 42u32;
            insert_deposit_with_graphs(&mut registry, deposit_idx);

            let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
            let pov_p2p_key: P2POperatorPubKey = operator_table.pov_p2p_key().clone();

            let sender_idx = TEST_NONPOV;
            let sender_p2p_key = operator_table.idx_to_p2p_key(&sender_idx).unwrap().clone();
            let graph_idx = GraphIdx {
                deposit: deposit_idx,
                operator: sender_idx,
            };

            let nag_request = NagRequest {
                recipient: pov_p2p_key,
                payload: NagRequestPayload::GraphNonces { graph_idx },
            };

            let msg = UnsignedGossipsubMsg::NagRequestExchange(nag_request);
            let result =
                classify_unsigned_gossip(&registry, &OperatorKey::Peer(&sender_p2p_key), &msg);

            assert_eq!(result.len(), 1, "Should create exactly one graph event");
            match &result[0] {
                SMEvent::Graph(boxed) => match boxed.as_ref() {
                    GraphEvent::NagReceived(evt) => {
                        assert!(matches!(evt.payload, NagRequestPayload::GraphNonces { .. }));
                        assert_eq!(evt.sender_operator_idx, sender_idx);
                    }
                    other => panic!("Expected graph NagReceived, got {other}"),
                },
                other => panic!("Expected Graph event, got {other:?}"),
            }
        }

        #[test]
        fn classify_graph_nag_request_not_addressed_to_pov_drops() {
            let mut registry = test_empty_registry();
            let deposit_idx = 42u32;
            insert_deposit_with_graphs(&mut registry, deposit_idx);

            let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
            let non_pov_idx = TEST_NONPOV;
            let non_pov_p2p_key: P2POperatorPubKey =
                operator_table.idx_to_p2p_key(&non_pov_idx).unwrap().clone();

            let sender_idx = TEST_POV_IDX;
            let sender_p2p_key = operator_table.idx_to_p2p_key(&sender_idx).unwrap().clone();
            let graph_idx = GraphIdx {
                deposit: deposit_idx,
                operator: non_pov_idx,
            };

            let nag_request = NagRequest {
                recipient: non_pov_p2p_key, // Not addressed to POV
                payload: NagRequestPayload::GraphNonces { graph_idx },
            };

            let msg = UnsignedGossipsubMsg::NagRequestExchange(nag_request);
            let result =
                classify_unsigned_gossip(&registry, &OperatorKey::Peer(&sender_p2p_key), &msg);

            assert!(
                result.is_empty(),
                "Should drop graph nag not addressed to POV"
            );
        }

        #[test]
        fn classify_graph_nag_request_unknown_sender_drops() {
            let mut registry = test_empty_registry();
            let deposit_idx = 42u32;
            insert_deposit_with_graphs(&mut registry, deposit_idx);

            let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
            let pov_p2p_key: P2POperatorPubKey = operator_table.pov_p2p_key().clone();
            let unknown_sender_key: P2POperatorPubKey = vec![0xffu8; 32].into();
            let graph_idx = GraphIdx {
                deposit: deposit_idx,
                operator: TEST_NONPOV,
            };

            let nag_request = NagRequest {
                recipient: pov_p2p_key,
                payload: NagRequestPayload::GraphNonces { graph_idx },
            };

            let msg = UnsignedGossipsubMsg::NagRequestExchange(nag_request);
            let result =
                classify_unsigned_gossip(&registry, &OperatorKey::Peer(&unknown_sender_key), &msg);

            assert!(
                result.is_empty(),
                "Should drop graph nag from unknown sender"
            );
        }

        #[test]
        #[should_panic(expected = "router should route nags only to existing deposit SMs")]
        fn classify_nag_request_missing_sm_panics_unreachable_via_router() {
            let registry = test_empty_registry(); // Empty registry - violates router invariant.

            let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
            let pov_p2p_key: P2POperatorPubKey = operator_table.pov_p2p_key().clone();
            let sender_p2p_key = operator_table.idx_to_p2p_key(&TEST_NONPOV).unwrap().clone();

            let nag_request = NagRequest {
                recipient: pov_p2p_key,
                payload: NagRequestPayload::DepositNonce { deposit_idx: 999 },
            };

            let msg = UnsignedGossipsubMsg::NagRequestExchange(nag_request);
            let _ = classify_unsigned_gossip(&registry, &OperatorKey::Peer(&sender_p2p_key), &msg);
        }
    }
}
