//! Message handler for the Strata Bridge P2P.

use bitcoin::{hashes::sha256, Txid, XOnlyPublicKey};
use libp2p::{identity::secp256k1::Keypair as Libp2pSecpKeypair, Multiaddr, PeerId};
use musig2::{PartialSignature, PubNonce};
use strata_p2p::{
    commands::{Command, ConnectToPeerCommand, UnsignedPublishMessage},
    events::Event,
    swarm::handle::P2PHandle,
};
use strata_p2p_types::{P2POperatorPubKey, Scope, SessionId, StakeChainId, WotsPublicKeys};
use strata_p2p_wire::p2p::v1::GetMessageRequest;
use tracing::{error, info, trace};

/// Message handler for the P2P client.
#[derive(Debug, Clone)]
pub struct MessageHandler {
    /// The P2P handle that is used to listen for events and call commands.
    pub handle: P2PHandle,

    /// The Libp2p secp256k1 keypair used for signing messages.
    pub keypair: Libp2pSecpKeypair,
}

impl MessageHandler {
    /// Creates a new message handler.
    pub fn new(handle: P2PHandle, keypair: Libp2pSecpKeypair) -> Self {
        Self { handle, keypair }
    }

    /// Starts listening for events and processing them.
    pub async fn listen_for_events(&mut self) {
        loop {
            match self.handle.next_event().await {
                Ok(Event::ReceivedMessage(msg)) => {
                    info!(?msg, "received message");
                    // Process the message based on its type
                    // You can add specific handling logic here
                }
                Err(e) => {
                    error!(?e, "error receiving event");
                    break;
                }
            }
        }
    }

    /// Connects to a peer, whitelists peer, and adds peer to the gossip network.
    pub async fn connect(&self, peer_id: PeerId, peer_addr: Multiaddr) {
        trace!(%peer_id, %peer_addr, "connecting to peer");
        self.handle
            .send_command(Command::ConnectToPeer(ConnectToPeerCommand {
                peer_id,
                peer_addr: peer_addr.clone(),
            }))
            .await;
        info!(%peer_id, %peer_addr, "connected to peer");
    }

    /// Dispatches an unsigned gossip message by signing it and sending it over the network.
    ///
    /// Internal use only.
    async fn dispatch(&self, msg: UnsignedPublishMessage, description: &str) {
        trace!(%description, ?msg, "sending message");
        let signed_msg = msg.sign_secp256k1(&self.keypair);
        self.handle.send_command(signed_msg).await;
        info!(%description, "sent message");
    }

    /// Requests information to an operator by signing it and sending it over the network.
    ///
    /// Internal use only.
    async fn request(&self, req: GetMessageRequest, description: &str) {
        trace!(%description, ?req, "sending request");
        let command = Command::RequestMessage(req);
        self.handle.send_command(command).await;
        info!(%description, "sent message");
    }

    /// Sends a deposit setup message to the network.
    pub async fn send_deposit_setup(
        &self,
        scope: Scope,
        hash: sha256::Hash,
        funding_txid: Txid,
        funding_vout: u32,
        operator_pk: XOnlyPublicKey,
        wots_pks: WotsPublicKeys,
    ) {
        let msg = UnsignedPublishMessage::DepositSetup {
            scope,
            hash,
            funding_txid,
            funding_vout,
            operator_pk,
            wots_pks,
        };
        self.dispatch(msg, "deposit setup message").await;
    }

    /// Sends a stake chain exchange message to the network.
    pub async fn send_stake_chain_exchange(
        &self,
        stake_chain_id: StakeChainId,
        pre_stake_txid: Txid,
        pre_stake_vout: u32,
    ) {
        let msg = UnsignedPublishMessage::StakeChainExchange {
            stake_chain_id,
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
    pub async fn request_deposit_setup(&self, scope: Scope, operator_pk: P2POperatorPubKey) {
        let req = GetMessageRequest::DepositSetup { scope, operator_pk };
        self.request(req, "Deposit setup request").await;
    }

    /// Requests a Stake chain exchange message from an operator.
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
