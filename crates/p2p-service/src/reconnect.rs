//! Background task that re-dials peers that have become disconnected.
//!
//! [`strata_p2p::swarm::P2P::establish_connections`] runs once at startup and does not retry
//! after a peer connection drops. When an operator restarts, the first outgoing dial often
//! fails (for example with `Address already in use` while the local port from the previous
//! process is still in `TIME_WAIT`), leaving the gossipsub mesh missing that peer until
//! libp2p's mesh-maintenance heuristics eventually re-graft — which can take minutes. The
//! task in this module turns that into a bounded retry loop driven by
//! [`Configuration::peer_reconnect_interval`](crate::Configuration::peer_reconnect_interval).

use std::time::Duration;

use libp2p::{Multiaddr, PeerId};
use strata_p2p::{commands::Command, swarm::handle::CommandHandle};
use tokio::time::MissedTickBehavior;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

/// Periodically checks each entry in `peers` and re-dials any peer that is no longer connected.
///
/// `peers` is a list of `(transport_id, address)` pairs identifying the peers and the addresses
/// at which they are expected to listen. The loop runs until `cancel` is triggered.
pub async fn maintain_connections(
    command_handle: CommandHandle,
    peers: Vec<(PeerId, Multiaddr)>,
    interval: Duration,
    cancel: CancellationToken,
) {
    if peers.is_empty() {
        debug!("no peers to maintain; reconnect task exiting");
        return;
    }
    info!(
        ?interval,
        peer_count = peers.len(),
        "starting peer reconnect task"
    );

    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);
    // The first tick fires immediately; skip it so we do not race with `establish_connections`.
    ticker.tick().await;

    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                debug!("peer reconnect task cancelled");
                return;
            }
            _ = ticker.tick() => {
                for (peer_id, addr) in &peers {
                    if command_handle.is_connected(peer_id, None).await {
                        continue;
                    }
                    debug!(%peer_id, %addr, "peer not connected, redialing");
                    if let Err(err) = redial(&command_handle, *peer_id, addr.clone()).await {
                        warn!(%peer_id, %addr, %err, "redial command rejected");
                    }
                }
            }
        }
    }
}

async fn redial(
    command_handle: &CommandHandle,
    transport_id: PeerId,
    addr: Multiaddr,
) -> Result<(), &'static str> {
    // `send_command` is fire-and-forget — it pushes onto an mpsc and returns. Any failure to
    // enqueue means the swarm task is gone, which we treat as a logical error.
    command_handle
        .send_command(Command::ConnectToPeer {
            transport_id,
            addresses: vec![addr],
        })
        .await;
    Ok(())
}
