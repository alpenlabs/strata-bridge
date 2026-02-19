//! This component classifies external events into those expected by specific state machines.

use std::{fmt::Display, ops::Deref};

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
    sm_registry::{OperatorKey, SMRegistry},
};

/// Wrapper for state-machine-specific events.
#[derive(Debug, Clone)]
pub enum SMEvent {
    /// An event related to the deposit state machine.
    Deposit(Box<DepositEvent>),
    /// An event related to the graph state machine.
    Graph(Box<GraphEvent>),
}

impl Deref for SMEvent {
    type Target = dyn std::fmt::Debug;

    fn deref(&self) -> &Self::Target {
        match self {
            SMEvent::Deposit(event) => event,
            SMEvent::Graph(event) => event,
        }
    }
}

impl Display for SMEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SMEvent::Deposit(event) => write!(f, "DepositEvent({event})"),
            SMEvent::Graph(event) => write!(f, "GraphEvent({event})"),
        }
    }
}

impl From<DepositEvent> for SMEvent {
    fn from(event: DepositEvent) -> Self {
        SMEvent::Deposit(Box::new(event))
    }
}

impl From<GraphEvent> for SMEvent {
    fn from(event: GraphEvent) -> Self {
        SMEvent::Graph(Box::new(event))
    }
}

/// Classifies the unified event into events specific to the state machines, if applicable.
#[expect(dead_code)]
fn classify(event: &UnifiedEvent, sm_registry: &SMRegistry) -> Vec<SMEvent> {
    match event {
        UnifiedEvent::OuroborosMessage(msg) => {
            classify_unsigned_gossip(sm_registry, &OperatorKey::Pov, msg)
        }

        UnifiedEvent::OuroborosRequest(_p2p_request) => unimplemented!("see STR-2329"),

        UnifiedEvent::Shutdown(_sender) => vec![], // not state-machine related

        UnifiedEvent::Block(_block_event) => vec![], // classified via `TxClassifier`

        UnifiedEvent::Assignment(entries) => classify_assignments(entries),

        UnifiedEvent::GossipMessage(gossipsub_msg) => classify_unsigned_gossip(
            sm_registry,
            &OperatorKey::Peer(&gossipsub_msg.key),
            &gossipsub_msg.unsigned,
        ),

        UnifiedEvent::ReqRespRequest {
            request: _,
            peer: _,
        } => unimplemented!("see STR-2329"),

        UnifiedEvent::NagTick => unimplemented!("see STR-2329"),

        UnifiedEvent::RetryTick => unimplemented!("see STR-2329"),
    }
}

/// Classifies an [`UnsignedGossipsubMsg`] into state-machine-specific events.
///
/// Both the ouroboros (self-published) and gossip (peer-received) paths use this function,
/// differing only in how the operator is identified via [`OperatorKey`].
fn classify_unsigned_gossip(
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
                        .map(|nonces| {
                            GraphEvent::NoncesReceived(GraphEvents::GraphNoncesReceivedEvent {
                                nonces,
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
                        .map(|partials| GraphEvent::PartialsReceived(
                            GraphEvents::GraphPartialsReceivedEvent {
                                partials,
                                operator_idx: op_idx,
                            },
                        ).into())
                    })
                    .collect(),
            }
        }
    }
}

/// Classifies assignment entries into state-machine-specific events.
fn classify_assignments(entries: &[AssignmentEntry]) -> Vec<SMEvent> {
    entries
        .iter()
        .map::<(SMEvent, SMEvent), _>(|entry| {
            // assignments are relevant to both the deposit and graph state machines, so we emit
            // events for both
            (
                DepositEvent::WithdrawalAssigned(DepositEvents::WithdrawalAssignedEvent {
                    assignee: entry.current_assignee(),
                    deadline: entry.fulfillment_deadline(),
                    recipient_desc: entry.withdrawal_command().destination().clone(),
                })
                .into(),
                GraphEvent::WithdrawalAssigned(GraphEvents::WithdrawalAssignedEvent {
                    assignee: entry.current_assignee(),
                    deadline: entry.fulfillment_deadline(),
                    recipient_desc: entry.withdrawal_command().destination().clone(),
                })
                .into(),
            )
        })
        .flat_map(|(deposit_event, graph_event)| vec![deposit_event, graph_event])
        .collect()
}
