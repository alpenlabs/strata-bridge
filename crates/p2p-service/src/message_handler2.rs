//! Message handler for the Strata Bridge P2P v2 with combined dispatch pattern.

use bitcoin::OutPoint;
use libp2p::futures::SinkExt;
use libp2p_identity::ed25519::Keypair;
use musig2::{PartialSignature, PubNonce};
use strata_bridge_p2p_types2::{
    GraphIdx, MuSig2Nonce, MuSig2Partial, PayoutDescriptor, UnsignedGossipsubMsg,
};
use strata_bridge_primitives::types::{DepositIdx, OperatorIdx};
use strata_p2p::{commands::GossipCommand, swarm::handle::GossipHandle};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, trace};

/// Message intended for oneself via ouroboros channel.
#[derive(Debug)]
pub struct OuroborosMessage {
    /// The unsigned message to process locally.
    pub publish: UnsignedGossipsubMsg,
}

/// Message handler for the bridge node.
#[derive(Debug, Clone)]
pub struct MessageHandler {
    /// For sending msgs to oneself (ouroboros pattern).
    ouroboros_msg_sender: mpsc::UnboundedSender<OuroborosMessage>,

    /// For direct gossip publishing.
    gossip_handle: GossipHandle,

    /// For signing messages.
    keypair: Keypair,
}

impl MessageHandler {
    /// Creates a new message handler.
    pub const fn new(
        ouroboros_msg_sender: mpsc::UnboundedSender<OuroborosMessage>,
        gossip_handle: GossipHandle,
        keypair: Keypair,
    ) -> Self {
        Self {
            ouroboros_msg_sender,
            gossip_handle,
            keypair,
        }
    }

    /// Sends a cooperative payout descriptor message.
    ///
    /// If `peer` is `Some`, sends directly to that peer. If `None`, broadcasts to all.
    pub async fn send_payout_descriptor(
        &mut self,
        deposit_idx: DepositIdx,
        operator_idx: OperatorIdx,
        operator_desc: PayoutDescriptor,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) {
        let msg = UnsignedGossipsubMsg::PayoutDescriptorExchange {
            deposit_idx,
            operator_idx,
            operator_desc,
        };
        self.dispatch(msg, peer, "payout descriptor exchange").await;
    }

    /// Sends the deposit-time data required to generate a graph.
    ///
    /// If `peer` is `Some`, sends directly to that peer. If `None`, broadcasts to all.
    pub async fn send_graph_data(
        &mut self,
        graph_idx: GraphIdx,
        funding_outpoint: OutPoint,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) {
        let msg = UnsignedGossipsubMsg::GraphDataExchange {
            graph_idx,
            claim_input: funding_outpoint.into(),
        };

        self.dispatch(msg, peer, "graph data exchange").await;
    }

    /// Sends a nonce for signing the deposit transaction.
    ///
    /// If `peer` is `Some`, sends directly to that peer. If `None`, broadcasts to all.
    pub async fn send_deposit_nonce(
        &mut self,
        deposit_idx: DepositIdx,
        nonce: PubNonce,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) {
        let msg = UnsignedGossipsubMsg::Musig2NoncesExchange(MuSig2Nonce::Deposit {
            deposit_idx,
            nonce: nonce.into(),
        });
        self.dispatch(msg, peer, "deposit nonce").await;
    }

    /// Sends a partial signature for the deposit transaction.
    ///
    /// If `peer` is `Some`, sends directly to that peer. If `None`, broadcasts to all.
    pub async fn send_deposit_partial(
        &mut self,
        deposit_idx: DepositIdx,
        partial: PartialSignature,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) {
        let msg = UnsignedGossipsubMsg::Musig2SignaturesExchange(MuSig2Partial::Deposit {
            deposit_idx,
            partial: partial.into(),
        });
        self.dispatch(msg, peer, "deposit partial").await;
    }

    /// Sends a payout nonce for cooperative payout signing.
    ///
    /// If `peer` is `Some`, sends directly to that peer. If `None`, broadcasts to all.
    pub async fn send_payout_nonce(
        &mut self,
        deposit_idx: DepositIdx,
        nonce: PubNonce,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) {
        let msg = UnsignedGossipsubMsg::Musig2NoncesExchange(MuSig2Nonce::Payout {
            deposit_idx,
            nonce: nonce.into(),
        });
        self.dispatch(msg, peer, "payout nonce").await;
    }

    /// Sends a payout partial signature for cooperative payout signing.
    ///
    /// If `peer` is `Some`, sends directly to that peer. If `None`, broadcasts to all.
    pub async fn send_payout_partial(
        &mut self,
        deposit_idx: DepositIdx,
        partial: PartialSignature,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) {
        let msg = UnsignedGossipsubMsg::Musig2SignaturesExchange(MuSig2Partial::Payout {
            deposit_idx,
            partial: partial.into(),
        });
        self.dispatch(msg, peer, "payout partial").await;
    }

    // --- Graph context (Vec of nonces/partials) ---

    /// Sends graph nonces for transaction graph signing.
    ///
    /// If `peer` is `Some`, sends directly to that peer. If `None`, broadcasts to all.
    pub async fn send_graph_nonces(
        &mut self,
        graph_idx: GraphIdx,
        nonces: Vec<PubNonce>,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) {
        let msg = UnsignedGossipsubMsg::Musig2NoncesExchange(MuSig2Nonce::Graph {
            graph_idx,
            nonces: nonces.into_iter().map(Into::into).collect(),
        });
        self.dispatch(msg, peer, "graph nonces").await;
    }

    /// Sends graph partial signatures for transaction graph signing.
    ///
    /// If `peer` is `Some`, sends directly to that peer. If `None`, broadcasts to all.
    pub async fn send_graph_partials(
        &mut self,
        graph_idx: GraphIdx,
        partials: Vec<PartialSignature>,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) {
        let msg = UnsignedGossipsubMsg::Musig2SignaturesExchange(MuSig2Partial::Graph {
            graph_idx,
            partials: partials.into_iter().map(Into::into).collect(),
        });
        self.dispatch(msg, peer, "graph partials").await;
    }

    async fn dispatch(
        &mut self,
        msg: UnsignedGossipsubMsg,
        peer: Option<oneshot::Sender<Vec<u8>>>,
        description: &str,
    ) {
        trace!(%description, ?msg, "sending message via combined dispatch");

        // 1. Sign message (borrows msg)
        let signed = msg.sign_ed25519(&self.keypair);
        let mut data = Vec::new();
        if let Err(e) = rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&signed, &mut data) {
            error!(%description, %e, "failed to serialize signed message");
            return;
        }

        // 2. Send unsigned to ouroboros for local processing (moves msg)
        if let Err(e) = self
            .ouroboros_msg_sender
            .send(OuroborosMessage { publish: msg })
        {
            error!(%description, %e, "failed to send message via ouroboros");
            return;
        }

        // 3. Send to network: directed to specific peer OR broadcast to all
        match peer {
            Some(channel) => {
                // Direct response to requesting peer
                if channel.send(data).is_err() {
                    error!(%description, "failed to send direct response to peer (receiver dropped)");
                    return;
                }
            }
            None => {
                // Broadcast to all peers via gossip
                if let Err(e) = self.gossip_handle.send(GossipCommand { data }).await {
                    error!(%description, %e, "failed to send message to gossip");
                    return;
                }
            }
        }

        debug!(%description, "sent message via combined dispatch");
    }
}
