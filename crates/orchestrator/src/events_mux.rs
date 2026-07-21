//! This component multiplexes multiple event streams into a single unified stream that can be
//! consumed downstream decoupling the event reception logic from the event processing logic.

use std::collections::VecDeque;

use btc_tracker::event::{BlockEvent, BlockStatus};
use futures::StreamExt;
use rkyv::rancor;
use strata_asm_proto_bridge_v1::AssignmentEntry;
use strata_asm_proto_bridge_v1_types::SafeHarbourAddress;
use strata_bridge_asm_events::event::AsmState;
use strata_bridge_p2p_service::message_handler::OuroborosMessage;
use strata_bridge_p2p_types::GossipsubMsg;
use strata_bridge_primitives::subscription::Subscription;
use strata_mosaic_client_api::MosaicEvent;
use strata_p2p::{
    events::GossipEvent,
    swarm::handle::{GossipHandle, ReqRespHandle},
};
use tracing::warn;

// NOTE: (@Rajil1213) the following use full `tokio` paths for disambiguation with `std` types.

/// All possible events that the orchestrator can receive.
#[derive(Debug)]
pub enum UnifiedEvent {
    /// Priority 0: Self-published gossip messages for consistent state.
    OuroborosMessage(OuroborosMessage),
    /// Priority 1: Graceful shutdown request.
    Shutdown,
    /// Priority 2: Buried bitcoin blocks from ZMQ.
    Block(BlockEvent),
    /// Priority 3: Assignment entries identified by the ASM runner.
    Assignment(Vec<AssignmentEntry>),
    /// Priority 3b: Per-block safe-harbour state from the ASM bridge subprotocol.
    SafeHarbour(SafeHarbourEvent),
    /// Priority 4a: Gossip messages received from peers.
    GossipMessage(GossipsubMsg),
    /// Priority 4b: Adaptor verified event from mosaic.
    MosaicEvent(MosaicEvent),
    /// Priority 5a: Periodic tick for nagging peers for missing messages.
    NagTick,
    /// Priority 5b: Periodic tick for retrying failed duties.
    RetryTick,
}

/// Per-block safe-harbour state from the ASM bridge subprotocol.
///
/// Not deposit-scoped, so it is handled by the pipeline/registry directly rather than routed
/// to specific state machines. Emitted for every buried block that carries a safe-harbour
/// snapshot; the registry latch acts only on `activated: true` and is idempotent.
#[derive(Debug, Clone)]
pub struct SafeHarbourEvent {
    /// Whether the ASM reports the safe harbour as activated.
    pub activated: bool,
    /// The frozen destination address; `Some` iff `activated`.
    pub address: Option<SafeHarbourAddress>,
}

/// A wrapper for holding all the input pins of the bridge and multiplexing them into a single
/// stream of [`UnifiedEvent`]'s that can be consumed by the state machines.
#[derive(Debug)]
pub struct EventsMux {
    /// Ouroboros channel for gossip messages.
    pub ouroboros_msg_rx: tokio::sync::mpsc::UnboundedReceiver<OuroborosMessage>,

    /// Shutdown signal receiver.
    pub shutdown_rx: Option<tokio::sync::oneshot::Receiver<()>>,

    /// Bitcoin block event stream.
    pub block_sub: Subscription<BlockEvent>,

    /// ASM state stream (assignments + safe harbour) from the ASM runner.
    pub asm_state_sub: Subscription<AsmState>,

    /// P2P handle for gossipsub messages.
    pub gossip_handle: GossipHandle,

    /// P2P channel for receiving requests from peers.
    pub req_resp_handle: ReqRespHandle,

    /// Mosaic event stream.
    pub mosaic_event_sub: Subscription<MosaicEvent>,

    /// Timer for nagging peers about missing messages.
    pub nag_tick: tokio::time::Interval,

    /// Timer for retrying failed duties.
    pub retry_tick: tokio::time::Interval,

    /// Events decomposed from a single upstream item and awaiting delivery across successive
    /// [`next`](Self::next) calls. One `AsmState` snapshot yields both a safe-harbour and an
    /// assignment event; the safe-harbour event is returned first and the assignment is buffered
    /// here. Initialize empty.
    pub pending: VecDeque<UnifiedEvent>,
}

impl EventsMux {
    /// Get the next available event, respecting the priority ordering.
    pub async fn next(&mut self) -> UnifiedEvent {
        loop {
            // Deliver any events buffered from a previously-decomposed upstream item (e.g. the
            // assignment event that trails a safe-harbour event from the same `AsmState`) before
            // polling the streams again.
            if let Some(event) = self.pending.pop_front() {
                return event;
            }

            tokio::select! {
                biased; // follow the same order as written below.

                // First, we prioritize the ouroboros channel since processing our own message is
                // necessary for having consistent state.
                Some(msg) = self.ouroboros_msg_rx.recv() => return UnifiedEvent::OuroborosMessage(msg),

                // Only now, we handle shutdown signals
                // so that we don't shutdown before our own messages and requests are processed.
                Ok(()) = async {
                    match self.shutdown_rx.as_mut() {
                        Some(rx) => rx.await,
                        None => std::future::pending().await, // If we've already processed a shutdown, we should never receive another one, so we can just await forever.
                    }
                } => {
                    self.shutdown_rx = None; // Ensure we only process shutdown once.
                    return UnifiedEvent::Shutdown;
                }

                // Now, we handle external event streams starting with buried bitcoin blocks.
                Some(block_event) = self.block_sub.next() => {
                    // skip unburied blocks
                    if block_event.status == BlockStatus::Buried {
                        return UnifiedEvent::Block(block_event);
                    }
                    // If the block is not buried, we ignore it and continue polling.
                }

                // Next, we handle ASM state (assignments + safe harbour) from the ASM runner, which
                // is also derived from bitcoin. A single snapshot decomposes into a safe-harbour
                // event (returned first, so the latch is set before assignment-driven work) and an
                // assignment event (buffered in `pending`).
                Some(state) = self.asm_state_sub.next() => {
                    self.pending.extend(asm_state_events(state));
                    // `asm_state_events` always yields at least the assignment event.
                    return self.pending.pop_front().expect("asm_state_events yields >= 1 event");
                }

                // Then, we handle gossip messages received from peers.
                Ok(GossipEvent::ReceivedMessage(raw_msg)) = self.gossip_handle.next_event() => {
                    let Some(msg) = decode_gossip_message(&raw_msg) else {
                        continue;
                    };

                    return UnifiedEvent::GossipMessage(msg);
                },

                Some(evt) = self.mosaic_event_sub.next() => return UnifiedEvent::MosaicEvent(evt),

                // Then, we handle the periodic nag tick for nagging peers about missing messages.
                // We do this toward the last because it's less urgent and prevents flooding the network
                // with requests that might be fulfilled by simply waiting some more.
                _nag_instant = self.nag_tick.tick() => return UnifiedEvent::NagTick,

                // Lastly, we retry failed duties as most duties have enough timeouts and very loose
                // deadlines (in the order of days).
                _retry_instant = self.retry_tick.tick() => return UnifiedEvent::RetryTick,
            }
        }
    }
}

/// Decomposes an [`AsmState`] snapshot into the ordered [`UnifiedEvent`]s it carries.
///
/// The safe-harbour event (present iff the ASM returned a safe-harbour snapshot) is ordered before
/// the assignment event so the registry latch is set before any assignment-driven work for the
/// same block. The assignment event is always emitted.
fn asm_state_events(state: AsmState) -> VecDeque<UnifiedEvent> {
    let mut events = VecDeque::with_capacity(2);
    if let Some(safe_harbour) = state.safe_harbour {
        events.push_back(UnifiedEvent::SafeHarbour(SafeHarbourEvent {
            activated: safe_harbour.is_activated(),
            address: safe_harbour.active_address().cloned(),
        }));
    }
    events.push_back(UnifiedEvent::Assignment(state.assignments));
    events
}

fn decode_gossip_message(raw_msg: &[u8]) -> Option<GossipsubMsg> {
    let Ok(msg) = rkyv::from_bytes::<GossipsubMsg, rancor::Error>(raw_msg) else {
        warn!("received invalid gossip message from peer");
        return None;
    };

    if !msg.verify() {
        warn!(peer = %msg.key, "received gossip message with invalid signature from peer");
        return None;
    }

    Some(msg)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use libp2p_identity::ed25519::Keypair;
    use rkyv::{rancor::Error, to_bytes};
    use strata_asm_proto_bridge_v1_types::{SafeHarbour, SafeHarbourAddress};
    use strata_bridge_p2p_types::{PayoutDescriptor, UnsignedGossipsubMsg};

    use super::{
        AsmState, SafeHarbourEvent, UnifiedEvent, asm_state_events, decode_gossip_message,
    };

    #[test]
    fn decode_gossip_message_rejects_invalid_inner_signature() {
        let keypair = Keypair::generate();
        let unsigned = UnsignedGossipsubMsg::PayoutDescriptorExchange {
            deposit_idx: 7,
            operator_idx: 3,
            operator_desc: PayoutDescriptor::new(vec![0xDE, 0xAD]),
        };
        let mut signed = unsigned.sign_ed25519(&keypair);
        signed.signature[0] ^= 0x01; // mess with the signature to make it invalid

        let raw_msg = to_bytes::<Error>(&signed).expect("serialize gossip message");

        assert!(
            decode_gossip_message(raw_msg.as_ref()).is_none(),
            "invalid inner signatures should be rejected before classification"
        );
    }

    fn safe_harbour_address() -> SafeHarbourAddress {
        let descriptor = bitcoin_bosd::Descriptor::new_p2tr(&[2u8; 32]).expect("valid x-only key");
        SafeHarbourAddress::try_from(descriptor).expect("p2tr accepted")
    }

    #[test]
    fn asm_state_events_orders_active_safe_harbour_before_assignment() {
        let address = safe_harbour_address();
        let mut safe_harbour = SafeHarbour::new(address.clone());
        safe_harbour.set_activated(true);

        let events = asm_state_events(AsmState {
            block_hash: bitcoin::BlockHash::all_zeros(),
            assignments: Vec::new(),
            safe_harbour: Some(safe_harbour),
        });

        let mut events = events.into_iter();
        assert!(matches!(
            events.next(),
            Some(UnifiedEvent::SafeHarbour(SafeHarbourEvent { activated: true, address: Some(a) })) if a == address
        ));
        assert!(matches!(events.next(), Some(UnifiedEvent::Assignment(_))));
        assert!(events.next().is_none());
    }

    #[test]
    fn asm_state_events_inactive_safe_harbour_carries_no_address() {
        let safe_harbour = SafeHarbour::new(safe_harbour_address()); // deactivated by default

        let events = asm_state_events(AsmState {
            block_hash: bitcoin::BlockHash::all_zeros(),
            assignments: Vec::new(),
            safe_harbour: Some(safe_harbour),
        });

        let mut events = events.into_iter();
        assert!(matches!(
            events.next(),
            Some(UnifiedEvent::SafeHarbour(SafeHarbourEvent {
                activated: false,
                address: None
            }))
        ));
        assert!(matches!(events.next(), Some(UnifiedEvent::Assignment(_))));
        assert!(events.next().is_none());
    }

    #[test]
    fn asm_state_events_without_safe_harbour_yields_only_assignment() {
        let events = asm_state_events(AsmState {
            block_hash: bitcoin::BlockHash::all_zeros(),
            assignments: Vec::new(),
            safe_harbour: None,
        });

        let mut events = events.into_iter();
        assert!(matches!(events.next(), Some(UnifiedEvent::Assignment(_))));
        assert!(events.next().is_none());
    }
}
