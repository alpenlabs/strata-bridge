//! This component multiplexes multiple event streams into a single unified stream that can be
//! consumed downstream decoupling the event reception logic from the event processing logic.

use btc_tracker::event::{BlockEvent, BlockStatus};
use futures::StreamExt;
use rkyv::rancor;
use strata_asm_proto_bridge_v1::AssignmentEntry;
use strata_bridge_asm_events::event::AssignmentsState;
use strata_bridge_p2p_service::message_handler::OuroborosMessage;
use strata_bridge_p2p_types::GossipsubMsg;
use strata_bridge_primitives::subscription::Subscription;
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
    /// Priority 4a: Gossip messages received from peers.
    GossipMessage(GossipsubMsg),
    /// Priority 5a: Periodic tick for nagging peers for missing messages.
    NagTick,
    /// Priority 5b: Periodic tick for retrying failed duties.
    RetryTick,
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

    /// Assignment entry stream from the ASM runner.
    pub assignments_sub: Subscription<AssignmentsState>,

    /// P2P handle for gossipsub messages.
    pub gossip_handle: GossipHandle,

    /// P2P channel for receiving requests from peers.
    pub req_resp_handle: ReqRespHandle,

    /// Timer for nagging peers about missing messages.
    pub nag_tick: tokio::time::Interval,

    /// Timer for retrying failed duties.
    pub retry_tick: tokio::time::Interval,
}

impl EventsMux {
    /// Get the next available event, respecting the priority ordering.
    pub async fn next(&mut self) -> UnifiedEvent {
        loop {
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

                // Next, we handle assignment entries from the ASM runner which are also observed from bitcoin.
                Some(state) = self.assignments_sub.next() => return UnifiedEvent::Assignment(state.assignments),

                // Then, we handle gossip messages received from peers.
                Ok(GossipEvent::ReceivedMessage(raw_msg)) = self.gossip_handle.next_event() => {
                    let Some(msg) = decode_gossip_message(&raw_msg) else {
                        continue;
                    };

                    return UnifiedEvent::GossipMessage(msg);
                },

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
    use libp2p_identity::ed25519::Keypair;
    use rkyv::{rancor::Error, to_bytes};
    use strata_bridge_p2p_types::{PayoutDescriptor, UnsignedGossipsubMsg};

    use super::decode_gossip_message;

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
}
