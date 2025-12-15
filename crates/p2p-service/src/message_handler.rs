//! Message handler for the Strata Bridge P2P.

use bitcoin::{hashes::sha256, OutPoint, Txid, XOnlyPublicKey};
use libp2p::identity::ed25519;
use musig2::{PartialSignature, PubNonce};
use p2p_types::{P2POperatorPubKey, Scope, SessionId, StakeChainId, WotsPublicKeys};
use p2p_wire::p2p::v1::{GetMessageRequest, GossipsubMsg, UnsignedGossipsubMsg};
use tokio::sync::{mpsc, oneshot};
use tracing::{debug, error, info, trace};

/// Message handler for the bridge node for relaying p2p messages.
///
/// This exposes an interface that allows publishing messages to the node itself as [`libbp2p`](https://docs.rs/libp2p/latest/libp2p/) does not support self-publishing.
// TODO: (@Rajil1213) rename this to `Outbox` and create a newtype that exposes the interface to
// read messages off of the p2p network (aka the `Inbox`).
#[derive(Debug, Clone)]
pub struct MessageHandler {
    /// The outbound channel used to self-publish gossipsub messages i.e., to send messages to
    /// itself rather than the network.
    ouroboros_msg_sender: mpsc::UnboundedSender<OuroborosMessage>,

    /// The outbound channel used to self-publish message requests.
    ///
    /// It is used when a node needs to nag itself. This mimics a duty retry mechanism and is
    /// useful if the node broadcasts a message to its peers that it then loses or fails to
    /// persist before an inopportune restart.
    ouroboros_req_sender: mpsc::UnboundedSender<GetMessageRequest>,
}

/// Message for the ouroboros channel.
#[derive(Debug)]
pub struct OuroborosMessage {
    /// An optional oneshot channel, representing the specific peer to send to. If `None`,
    /// the data will be broadcast to all peers.
    pub peer: Option<oneshot::Sender<Vec<u8>>>,
    /// The unsigned publish message that needs to be sent.
    pub publish: UnsignedPublishMessage,
}

impl MessageHandler {
    /// Creates a new message handler.
    pub const fn new(
        ouroboros_msg_sender: mpsc::UnboundedSender<OuroborosMessage>,
        ouroboros_req_sender: mpsc::UnboundedSender<GetMessageRequest>,
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
    async fn dispatch(
        &self,
        msg: UnsignedPublishMessage,
        peer: Option<oneshot::Sender<Vec<u8>>>,
        description: &str,
    ) {
        trace!(%description, ?msg, "sending message");
        // let signed_msg = self.handle.sign_message(msg.clone());
        // self.handle.send_command(signed_msg.clone()).await;

        if let Err(e) = self
            .ouroboros_msg_sender
            .send(OuroborosMessage { peer, publish: msg })
        {
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
    #[allow(clippy::too_many_arguments)]
    pub async fn send_deposit_setup(
        &self,
        index: u32,
        scope: Scope,
        hash: sha256::Hash,
        funding_outpoint: OutPoint,
        operator_pk: XOnlyPublicKey,
        wots_pks: WotsPublicKeys,
        peer: Option<oneshot::Sender<Vec<u8>>>,
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
        self.dispatch(msg, peer, "deposit setup message").await;
    }

    /// Sends a stake chain exchange message to the network.
    pub async fn send_stake_chain_exchange(
        &self,
        stake_chain_id: StakeChainId,
        operator_pk: XOnlyPublicKey,
        pre_stake_txid: Txid,
        pre_stake_vout: u32,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) {
        let msg = UnsignedPublishMessage::StakeChainExchange {
            stake_chain_id,
            operator_pk,
            pre_stake_txid,
            pre_stake_vout,
        };
        self.dispatch(msg, peer, "stake chain exchange message")
            .await;
    }

    /// Sends a MuSig2 nonces exchange message to the network.
    pub async fn send_musig2_nonces(
        &self,
        session_id: SessionId,
        pub_nonces: Vec<PubNonce>,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) {
        let msg = UnsignedPublishMessage::Musig2NoncesExchange {
            session_id,
            pub_nonces,
        };
        self.dispatch(msg, peer, "MuSig2 nonces exchange message")
            .await;
    }

    /// Sends a MuSig2 signatures exchange message to the network.
    pub async fn send_musig2_signatures(
        &self,
        session_id: SessionId,
        partial_sigs: Vec<PartialSignature>,
        peer: Option<oneshot::Sender<Vec<u8>>>,
    ) {
        let msg = UnsignedPublishMessage::Musig2SignaturesExchange {
            session_id,
            partial_sigs,
        };
        self.dispatch(msg, peer, "MuSig2 signatures exchange message")
            .await;
    }

    /// Requests a deposit setup message from an operator.
    ///
    /// The user needs to wait for the response by [`Poll`](std::task::Poll)ing the associated
    /// [`ReqRespHandle`](strata_p2p::swarm::handle::ReqRespHandle).
    pub async fn request_deposit_setup(&self, scope: Scope, operator_pk: P2POperatorPubKey) {
        let req = GetMessageRequest::DepositSetup { scope, operator_pk };
        self.request(req, "Deposit setup request").await;
    }

    /// Requests a Stake chain exchange message from an operator.
    ///
    /// The user needs to wait for the response by [`Poll`](std::task::Poll)ing the associated
    /// [`ReqRespHandle`](strata_p2p::swarm::handle::ReqRespHandle).
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
    /// [`ReqRespHandle`](strata_p2p::swarm::handle::ReqRespHandle).
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
    /// [`ReqRespHandle`](strata_p2p::swarm::handle::ReqRespHandle).
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

/// Signed version of [`UnsignedPublishMessage`].
#[derive(Debug, Clone)]
pub struct PublishMessage {
    /// Operator's P2P public key.
    pub key: P2POperatorPubKey,

    /// Operator's signature over the message.
    pub signature: Vec<u8>,

    /// Unsigned message.
    pub msg: UnsignedPublishMessage,
}

/// Types of unsigned messages.
#[derive(Debug, Clone)]
#[expect(clippy::large_enum_variant)]
pub enum UnsignedPublishMessage {
    /// Stake Chain information.
    StakeChainExchange {
        /// 32-byte hash of some unique to stake chain data.
        stake_chain_id: StakeChainId,

        /// 32-byte x-only public key of the operator used to advance the stake chain.
        operator_pk: XOnlyPublicKey,

        /// [`Txid`] of the pre-stake transaction.
        pre_stake_txid: Txid,

        /// vout index of the pre-stake transaction.
        pre_stake_vout: u32,
    },

    /// Deposit setup.
    ///
    /// Primarily used for the WOTS PKs.
    DepositSetup {
        /// The deposit [`Scope`].
        scope: Scope,

        /// Index of the deposit.
        index: u32,

        /// [`sha256::Hash`] hash of the stake transaction that the preimage is revealed when
        /// advancing the stake.
        hash: sha256::Hash,

        /// Funding transaction ID.
        ///
        /// Used to cover the dust outputs in the transaction graph connectors.
        funding_txid: Txid,

        /// Funding transaction output index.
        ///
        /// Used to cover the dust outputs in the transaction graph connectors.
        funding_vout: u32,

        /// Operator's X-only public key to construct a P2TR address to reimburse the
        /// operator for a valid withdraw fulfillment.
        operator_pk: XOnlyPublicKey,

        /// Winternitz One-Time Signature (WOTS) public keys shared in a deposit.
        wots_pks: WotsPublicKeys,
    },

    /// MuSig2 (public) nonces exchange.
    Musig2NoncesExchange {
        /// The [`SessionId`].
        session_id: SessionId,

        /// Payload, (public) nonces.
        pub_nonces: Vec<PubNonce>,
    },

    /// MuSig2 (partial) signatures exchange.
    Musig2SignaturesExchange {
        /// The [`SessionId`].
        session_id: SessionId,

        /// Payload, (partial) signatures.
        partial_sigs: Vec<PartialSignature>,
    },
}

impl From<PublishMessage> for GossipsubMsg {
    /// Converts [`PublishMessage`] into [`GossipsubMsg`].
    fn from(value: PublishMessage) -> Self {
        GossipsubMsg {
            signature: value.signature,
            key: value.key,
            unsigned: value.msg.into(),
        }
    }
}

impl UnsignedPublishMessage {
    /// Signs `self` using supplied [`ed25519::Keypair`]. Returns a `Command`
    /// with resulting signature and public key from [`ed25519::Keypair`].
    pub fn sign_ed25519(&self, keypair: &ed25519::Keypair) -> PublishMessage {
        let kind: UnsignedGossipsubMsg = self.clone().into();
        let msg = kind.content();
        let signature = keypair.sign(&msg);

        PublishMessage {
            key: keypair.public().clone().into(),
            signature,
            msg: self.clone(),
        }
    }
}

impl From<UnsignedPublishMessage> for UnsignedGossipsubMsg {
    /// Converts [`UnsignedPublishMessage`] into [`UnsignedGossipsubMsg`].
    fn from(value: UnsignedPublishMessage) -> Self {
        match value {
            UnsignedPublishMessage::StakeChainExchange {
                stake_chain_id,
                operator_pk,
                pre_stake_txid,
                pre_stake_vout,
            } => UnsignedGossipsubMsg::StakeChainExchange {
                stake_chain_id,
                operator_pk: operator_pk.into(),
                pre_stake_txid: pre_stake_txid.into(),
                pre_stake_vout,
            },

            UnsignedPublishMessage::DepositSetup {
                scope,
                index,
                hash,
                funding_txid,
                funding_vout,
                operator_pk,
                wots_pks,
            } => UnsignedGossipsubMsg::DepositSetup {
                scope,
                index,
                hash: hash.into(),
                funding_txid: funding_txid.into(),
                funding_vout,
                operator_pk: operator_pk.into(),
                wots_pks,
            },

            UnsignedPublishMessage::Musig2NoncesExchange {
                session_id,
                pub_nonces,
            } => UnsignedGossipsubMsg::Musig2NoncesExchange {
                session_id,
                nonces: pub_nonces.into_iter().map(Into::into).collect(),
            },

            UnsignedPublishMessage::Musig2SignaturesExchange {
                session_id,
                partial_sigs,
            } => UnsignedGossipsubMsg::Musig2SignaturesExchange {
                session_id,
                signatures: partial_sigs.into_iter().map(Into::into).collect(),
            },
        }
    }
}
