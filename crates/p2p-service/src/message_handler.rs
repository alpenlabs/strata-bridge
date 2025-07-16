//! Message handler for the Strata Bridge P2P.

use bitcoin::{hashes::sha256, OutPoint, Txid, XOnlyPublicKey};
use musig2::{PartialSignature, PubNonce};
use strata_p2p::commands::UnsignedPublishMessage;
use strata_p2p_types::{P2POperatorPubKey, Scope, SessionId, StakeChainId, WotsPublicKeys};
use strata_p2p_wire::p2p::v1::GetMessageRequest;
use tokio::sync::broadcast;
use tracing::{debug, error, info, trace};

/// Message handler for the bridge node for relaying p2p messages.
///
/// This exposes an interface that allows publishing messages to the node itself as [`libbp2p`](https://docs.rs/libp2p/latest/libp2p/) does not support self-publishing.
// TODO: (@Rajil1213) rename this to `Outbox` and create a newtype for `P2PHandle` that exposes the
// interface to read messages off of the p2p network (aka the `Inbox`).
#[derive(Debug, Clone)]
pub struct MessageHandler {
    /// The outbound channel used to self-publish gossipsub messages i.e., to send messages to
    /// itself rather than the network.
    ouroboros_msg_sender: broadcast::Sender<UnsignedPublishMessage>,

    /// The outbound channel used to self-publish message requests.
    ///
    /// It is used when a node needs to nag itself. This mimics a duty retry mechanism and is
    /// useful if the node broadcasts a message to its peers that it then loses or fails to
    /// persist before an inopportune restart.
    ouroboros_req_sender: broadcast::Sender<GetMessageRequest>,
}

impl MessageHandler {
    /// Creates a new message handler.
    pub const fn new(
        ouroboros_msg_sender: broadcast::Sender<UnsignedPublishMessage>,
        ouroboros_req_sender: broadcast::Sender<GetMessageRequest>,
    ) -> Self {
        Self {
            ouroboros_msg_sender,
            ouroboros_req_sender,
        }
    }

    /// Dispatches an unsigned gossip message by signing it and sending it over the network as well
    /// as to the node itself.
    ///
    /// Internal use only.
    async fn dispatch(&self, msg: UnsignedPublishMessage, description: &str) {
        trace!(%description, ?msg, "sending message");
        // let signed_msg = self.handle.sign_message(msg.clone());
        // self.handle.send_command(signed_msg.clone()).await;

        if let Err(e) = self.ouroboros_msg_sender.send(msg) {
            error!(%description, %e, "failed to send message via ouroboros");

            return;
        };

        debug!(%description, "sent message");
    }

    /// Requests information from an operator by signing it and sending it over the network.
    ///
    /// Internal use only.
    async fn request(&self, req: GetMessageRequest, description: &str) {
        trace!(%description, ?req, "sending request");
        if let Err(e) = self.ouroboros_req_sender.send(req) {
            error!(%description, %e, "failed to send request via ouroboros");

            return;
        }

        info!(%description, "sent request");
    }

    /// Sends a deposit setup message to the network.
    pub async fn send_deposit_setup(
        &self,
        index: u32,
        scope: Scope,
        hash: sha256::Hash,
        funding_outpoint: OutPoint,
        operator_pk: XOnlyPublicKey,
        wots_pks: WotsPublicKeys,
    ) {
        let msg = UnsignedPublishMessage::DepositSetup {
            scope,
            index,
            hash,
            funding_txid: funding_outpoint.txid,
            funding_vout: funding_outpoint.vout,
            operator_pk,
            wots_pks,
        };
        self.dispatch(msg, "deposit setup message").await;
    }

    /// Sends a stake chain exchange message to the network.
    pub async fn send_stake_chain_exchange(
        &self,
        stake_chain_id: StakeChainId,
        operator_pk: XOnlyPublicKey,
        pre_stake_txid: Txid,
        pre_stake_vout: u32,
    ) {
        let msg = UnsignedPublishMessage::StakeChainExchange {
            stake_chain_id,
            operator_pk,
            pre_stake_txid,
            pre_stake_vout,
        };
        self.dispatch(msg, "stake chain exchange message").await;
    }

    /// Sends a MuSig2 nonces exchange message to the network.
    pub async fn send_musig2_nonces(&self, session_id: SessionId, pub_nonces: Vec<PubNonce>) {
        let msg = UnsignedPublishMessage::Musig2NoncesExchange {
            session_id,
            pub_nonces,
        };
        self.dispatch(msg, "MuSig2 nonces exchange message").await;
    }

    /// Sends a MuSig2 signatures exchange message to the network.
    pub async fn send_musig2_signatures(
        &self,
        session_id: SessionId,
        partial_sigs: Vec<PartialSignature>,
    ) {
        let msg = UnsignedPublishMessage::Musig2SignaturesExchange {
            session_id,
            partial_sigs,
        };
        self.dispatch(msg, "MuSig2 signatures exchange message")
            .await;
    }

    /// Requests a deposit setup message from an operator.
    ///
    /// The user needs to wait for the response by [`Poll`](std::task::Poll)ing the associated
    /// [`P2PHandle`](strata_p2p::swarm::handle::P2PHandle).
    pub async fn request_deposit_setup(&self, scope: Scope, operator_pk: P2POperatorPubKey) {
        let req = GetMessageRequest::DepositSetup { scope, operator_pk };
        self.request(req, "Deposit setup request").await;
    }

    /// Requests a Stake chain exchange message from an operator.
    ///
    /// The user needs to wait for the response by [`Poll`](std::task::Poll)ing the associated
    /// [`P2PHandle`](strata_p2p::swarm::handle::P2PHandle).
    pub async fn request_stake_chain_exchange(
        &self,
        stake_chain_id: StakeChainId,
        operator_pk: P2POperatorPubKey,
    ) {
        let req = GetMessageRequest::StakeChainExchange {
            stake_chain_id,
            operator_pk,
        };
        self.request(req, "Stake chain exchange request").await;
    }

    /// Requests a MuSig2 nonces exchange message from an operator.
    ///
    /// The user needs to wait for the response by [`Poll`](std::task::Poll)ing the associated
    /// [`P2PHandle`](strata_p2p::swarm::handle::P2PHandle).
    pub async fn request_musig2_nonces(
        &self,
        session_id: SessionId,
        operator_pk: P2POperatorPubKey,
    ) {
        let req = GetMessageRequest::Musig2NoncesExchange {
            session_id,
            operator_pk,
        };
        self.request(req, "MuSig2 nonces exchange request").await;
    }

    /// Requests a MuSig2 signatures exchange message from an operator.
    ///
    /// The user needs to wait for the response by [`Poll`](std::task::Poll)ing the associated
    /// [`P2PHandle`](strata_p2p::swarm::handle::P2PHandle).
    pub async fn request_musig2_signatures(
        &self,
        session_id: SessionId,
        operator_pk: P2POperatorPubKey,
    ) {
        let req = GetMessageRequest::Musig2SignaturesExchange {
            session_id,
            operator_pk,
        };
        self.request(req, "MuSig2 signatures exchange request")
            .await;
    }
}
