//! This component multiplexes multiple event streams into a single unified stream that can be
//! consumed downstream decoupling the event reception logic from the event processing logic.

use btc_tracker::event::{BlockEvent, BlockStatus};
use futures::StreamExt;
use rkyv::rancor;
use strata_asm_proto_bridge_v1::AssignmentEntry;
use strata_bridge_p2p_types2::{GossipsubMsg, UnsignedGossipsubMsg};
use strata_bridge_p2p_wire::p2p::v1::GetMessageRequest; /* FIXME: (@Rajil1213) this is
                                                          * temporary until we have it in
                                                          * `p2p_types2`. */
use strata_bridge_primitives::subscription::Subscription;
use strata_p2p::{
    events::{GossipEvent, ReqRespEvent},
    swarm::handle::{GossipHandle, ReqRespHandle},
};
use tracing::warn;

// NOTE: (@Rajil1213) the following use full `tokio` paths for disambiguation with `std` types.

/// All possible events that the orchestrator can receive.
#[derive(Debug)]
pub enum UnifiedEvent {
    /// Priority 0: Self-published gossip messages for consistent state.
    OuroborosMessage(UnsignedGossipsubMsg),
    /// Priority 1: Self-published nag requests.
    OuroborosRequest(GetMessageRequest),
    /// Priority 2: Graceful shutdown request.
    Shutdown(tokio::sync::oneshot::Sender<()>),
    /// Priority 3: Buried bitcoin blocks from ZMQ.
    Block(BlockEvent),
    /// Priority 4: Assignment entries identified by the ASM runner.
    Assignment(Vec<AssignmentEntry>),
    /// Priority 5a: Gossip messages received from peers.
    GossipMessage(GossipsubMsg),
    /// Priority 5b: Requests received from peers.
    ReqRespRequest {
        /// The request received from the peer.
        request: GetMessageRequest,
        /// The peer that sent the request.
        peer: Option<tokio::sync::oneshot::Sender<Vec<u8>>>,
    },
    /// Priority 6a: Periodic tick for nagging peers for missing messages.
    NagTick,
    /// Priority 6b: Periodic tick for retrying failed duties.
    RetryTick,
}

/// A wrapper for holding all the input pins of the bridge and multiplexing them into a single
/// stream of [`UnifiedEvent`]'s that can be consumed by the state machines.
#[derive(Debug)]
pub struct EventsMux {
    /// Ouroboros channel for gossip messages.
    pub ouroboros_msg_rx: tokio::sync::mpsc::UnboundedReceiver<UnsignedGossipsubMsg>,

    /// Ouroboros channel for nag requests.
    pub ouroboros_req_rx: tokio::sync::mpsc::UnboundedReceiver<GetMessageRequest>,

    /// Shutdown signal receiver.
    pub shutdown_rx: Option<tokio::sync::oneshot::Receiver<tokio::sync::oneshot::Sender<()>>>,

    /// Bitcoin block event stream.
    pub block_sub: Subscription<BlockEvent>,

    /// Assignment entry stream from the ASM runner.
    pub assignments_sub: Subscription<Vec<AssignmentEntry>>,

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

                // And similarly, our own requests
                Some(req) = self.ouroboros_req_rx.recv() => return UnifiedEvent::OuroborosRequest(req),

                // Only now, we handle shutdown signals
                // so that we don't shutdown before our own messages and requests are processed.
                Ok(shutdown_sender) = async {
                    match self.shutdown_rx.as_mut() {
                        Some(rx) => rx.await,
                        None => std::future::pending().await, // If we've already processed a shutdown, we should never receive another one, so we can just await forever.
                    }
                } => {
                    self.shutdown_rx = None; // Ensure we only process shutdown once.
                    return UnifiedEvent::Shutdown(shutdown_sender);
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
                Some(assignments) = self.assignments_sub.next() => return UnifiedEvent::Assignment(assignments),

                // Then, we handle gossip messages received from peers.
                Ok(GossipEvent::ReceivedMessage(raw_msg)) = self.gossip_handle.next_event() => {
                    let Ok(msg) = rkyv::from_bytes::<GossipsubMsg, rancor::Error>(&raw_msg) else {
                        // If we fail to deserialize the message, we ignore it and continue polling.
                        warn!("received invalid gossip message from peer");
                        continue;
                    };

                    return UnifiedEvent::GossipMessage(msg);
                },

                // And similarly, the requests received from peers.
                Some(ReqRespEvent::ReceivedRequest(raw_msg, peer_channel)) = self.req_resp_handle.next_event() => {
                    let Ok(request) = rkyv::from_bytes::<GetMessageRequest, rancor::Error>(&raw_msg) else {
                        // If we fail to deserialize the request, we ignore it and continue polling.
                        warn!("received invalid request from peer");
                        continue;
                    };

                    return UnifiedEvent::ReqRespRequest {
                        request,
                        peer: Some(peer_channel),
                    };
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
