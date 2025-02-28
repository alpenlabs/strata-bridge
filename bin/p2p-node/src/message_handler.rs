//! Message handler for the P2P client.

use bitcoin::{OutPoint, XOnlyPublicKey};
use libp2p::identity::secp256k1::Keypair as Libp2pSecpKeypair;
use musig2::{PartialSignature, PubNonce};
use strata_p2p::{commands::UnsignedPublishMessage, events::Event, swarm::handle::P2PHandle};
use strata_p2p_types::{Scope, SessionId, StakeChainId, StakeData, WotsPublicKeys};
use tracing::{error, info, trace};

/// Message handler for the P2P client.
#[derive(Debug)]
pub(crate) struct MessageHandler {
    /// The P2P handle that is used to listen for events and call commands.
    pub(crate) handle: P2PHandle,

    /// The Libp2p secp256k1 keypair used for signing messages.
    pub(crate) keypair: Libp2pSecpKeypair,
}

impl MessageHandler {
    /// Creates a new message handler.
    pub(crate) fn new(handle: P2PHandle, keypair: Libp2pSecpKeypair) -> Self {
        Self { handle, keypair }
    }

    /// Starts listening for events and processing them.
    pub(crate) async fn listen_for_events(&mut self) {
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

    /// Dispatches an unsigned message by signing it and sending it over the network.
    pub(crate) async fn dispatch(&self, msg: UnsignedPublishMessage, description: &str) {
        trace!(%description, ?msg, "sending message");
        let signed_msg = msg.sign_secp256k1(&self.keypair);
        self.handle.send_command(signed_msg).await;
        info!(%description, "sent message");
    }

    /// Sends a deposit setup message to the network.
    pub(crate) async fn send_deposit_setup(&self, scope: Scope, wots_pks: WotsPublicKeys) {
        let msg = UnsignedPublishMessage::DepositSetup { scope, wots_pks };
        self.dispatch(msg, "deposit setup message").await;
    }

    /// Sends a stake chain exchange message to the network.
    pub(crate) async fn send_stake_chain_exchange(
        &self,
        stake_chain_id: StakeChainId,
        pre_stake_outpoint: OutPoint,
        checkpoint_pubkeys: Vec<XOnlyPublicKey>,
        stake_data: Vec<StakeData>,
    ) {
        let msg = UnsignedPublishMessage::StakeChainExchange {
            stake_chain_id,
            pre_stake_outpoint,
            checkpoint_pubkeys,
            stake_data,
        };
        self.dispatch(msg, "stake chain exchange message").await;
    }

    /// Sends a MuSig2 nonces exchange message to the network.
    pub(crate) async fn send_musig2_nonces(
        &self,
        session_id: SessionId,
        pub_nonces: Vec<PubNonce>,
    ) {
        let msg = UnsignedPublishMessage::Musig2NoncesExchange {
            session_id,
            pub_nonces,
        };
        self.dispatch(msg, "MuSig2 nonces exchange message").await;
    }

    /// Sends a MuSig2 signatures exchange message to the network.
    pub(crate) async fn send_musig2_signatures(
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
}
