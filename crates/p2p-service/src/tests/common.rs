//! Helper functions for the P2P tests.

use std::time::Duration;

use anyhow::bail;
use bitcoin::{
    hashes::{sha256, Hash},
    Txid, XOnlyPublicKey,
};
use futures::{future::join_all, SinkExt};
use libp2p::{
    build_multiaddr,
    identity::{ed25519::Keypair as EdKeypair, Keypair},
    Multiaddr, PeerId,
};
use strata_bridge_p2p_types::{P2POperatorPubKey, Scope, SessionId, StakeChainId, WotsPublicKeys};
use strata_bridge_p2p_wire::p2p::v1::{ArchivedGossipsubMsg, GossipsubMsg, UnsignedGossipsubMsg};
use strata_bridge_test_utils::musig2::{generate_partial_signature, generate_pubnonce};
use strata_p2p::{
    commands::GossipCommand,
    events::GossipEvent,
    swarm::{
        self,
        handle::{GossipHandle, ReqRespHandle},
        P2PConfig, P2P,
    },
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{info, trace};

use crate::message_handler::{PublishMessage, UnsignedPublishMessage};

pub(crate) struct Operator {
    pub(crate) p2p: P2P,
    pub(crate) gossip_handle: GossipHandle,
    pub(crate) req_resp_handle: ReqRespHandle,
    pub(crate) kp: EdKeypair,
}

impl Operator {
    pub(crate) fn new(
        keypair: EdKeypair,
        connect_to: Vec<Multiaddr>,
        local_addr: Multiaddr,
        cancel: CancellationToken,
        dial_timeout: Option<Duration>,
        general_timeout: Option<Duration>,
        connection_check_interval: Option<Duration>,
    ) -> anyhow::Result<Self> {
        let config = P2PConfig {
            transport_keypair: keypair.clone().into(),
            idle_connection_timeout: Duration::from_secs(30),
            max_retries: Some(5),
            listening_addrs: vec![local_addr],
            connect_to,
            dial_timeout,
            general_timeout,
            connection_check_interval,
            protocol_name: None,
            channel_timeout: None,
            gossipsub_topic: None,
            gossipsub_max_transmit_size: None,
            gossipsub_score_params: None,
            gossipsub_score_thresholds: None,
            gossip_event_buffer_size: None,
            commands_event_buffer_size: None,
            command_buffer_size: None,
            handle_default_timeout: None,
            req_resp_event_buffer_size: None,
            req_resp_command_buffer_size: None,
            request_max_bytes: None,
            response_max_bytes: None,
            gossip_command_buffer_size: None,
            envelope_max_age: None,
            max_clock_skew: None,
            kad_protocol_name: None,
            kad_record_ttl: None,
            kad_timer_putrecorderror: None,
            conn_limits: Default::default(),
        };

        let swarm = swarm::with_inmemory_transport(&config)?;
        let (p2p, req_resp_handle) = P2P::from_config(config, cancel, swarm, None, None)?;
        let gossip_handle = p2p.new_gossip_handle();

        Ok(Self {
            gossip_handle,
            req_resp_handle,
            p2p,
            kp: keypair,
        })
    }
}

/// Auxiliary structure to control operators from outside.
pub(crate) struct OperatorHandle {
    pub(crate) gossip_handle: GossipHandle,
    pub(crate) req_resp_handle: ReqRespHandle,
    pub(crate) peer_id: PeerId,
    pub(crate) kp: EdKeypair,
}

pub(crate) struct Setup {
    pub(crate) cancel: CancellationToken,
    pub(crate) operators: Vec<OperatorHandle>,
    pub(crate) tasks: TaskTracker,
}

impl Setup {
    /// Spawn `n` operators that are connected "all-to-all" with handles to them, task tracker
    /// to stop control async tasks they are spawned in.
    pub(crate) async fn all_to_all(n: usize) -> anyhow::Result<Self> {
        let (keypairs, peer_ids, multiaddresses) = Self::setup_keys_ids_addrs_of_n_operators(n);
        trace!(?keypairs, ?peer_ids, ?multiaddresses, "setup nodes");

        let cancel = CancellationToken::new();
        let mut operators = Vec::new();

        for (idx, (keypair, addr)) in keypairs.iter().zip(&multiaddresses).enumerate() {
            let mut other_addrs = multiaddresses.clone();
            other_addrs.remove(idx);
            let mut other_peerids = peer_ids.clone();
            other_peerids.remove(idx);

            let operator = Operator::new(
                keypair.clone(),
                other_addrs,
                addr.clone(),
                cancel.child_token(),
                Some(Duration::from_millis(250)),
                Some(Duration::from_millis(250)),
                Some(Duration::from_millis(500)),
            )?;

            operators.push(operator);
        }

        let (operators, tasks) = Self::start_operators(operators).await;

        // Wait for gossipsub mesh to stabilize.
        // The gossipsub heartbeat_initial_delay is 5 seconds by default,
        // so we need to wait at least that long for subscriptions to propagate
        // between peers. Adding 1 extra second for safety margin.
        info!("Waiting for gossipsub mesh to stabilize...");
        tokio::time::sleep(Duration::from_secs(6)).await;
        info!("Gossipsub mesh should be stable now");

        Ok(Self {
            cancel,
            tasks,
            operators,
        })
    }

    /// Spawn `n` operators that are connected "all-to-all" with handles to them, task tracker
    /// to stop control async tasks they are spawned in with an extra signers allowlist.
    #[expect(dead_code)]
    pub(crate) async fn with_extra_signers(
        number: usize,
        extra_signers: Vec<P2POperatorPubKey>,
    ) -> anyhow::Result<Self> {
        let (keypairs, peer_ids, multiaddresses) =
            Self::setup_keys_ids_addrs_of_n_operators(number);

        let cancel = CancellationToken::new();
        let mut operators = Vec::new();
        let mut signers_allowlist: Vec<P2POperatorPubKey> = keypairs
            .clone()
            .into_iter()
            .map(|kp| kp.public().clone().into())
            .collect();

        // Add the extra signers to the allowlist
        signers_allowlist.extend(extra_signers);

        for (idx, (keypair, addr)) in keypairs.iter().zip(&multiaddresses).enumerate() {
            let mut other_addrs = multiaddresses.clone();
            other_addrs.remove(idx);
            let mut other_peerids = peer_ids.clone();
            other_peerids.remove(idx);

            let operator = Operator::new(
                keypair.clone(),
                other_addrs,
                addr.clone(),
                cancel.child_token(),
                Some(Duration::from_millis(250)),
                Some(Duration::from_millis(250)),
                Some(Duration::from_millis(500)),
            )?;

            operators.push(operator);
        }

        let (operators, tasks) = Self::start_operators(operators).await;

        // Wait for gossipsub mesh to stabilize.
        // The gossipsub heartbeat_initial_delay is 5 seconds by default,
        // so we need to wait at least that long for subscriptions to propagate
        // between peers. Adding 1 extra second for safety margin.
        info!("Waiting for gossipsub mesh to stabilize...");
        tokio::time::sleep(Duration::from_secs(6)).await;
        info!("Gossipsub mesh should be stable now");

        Ok(Self {
            cancel,
            tasks,
            operators,
        })
    }

    /// Create `n` random keypairs, peer ids from them and sequential in-memory
    /// addresses.
    fn setup_keys_ids_addrs_of_n_operators(
        n: usize,
    ) -> (Vec<EdKeypair>, Vec<PeerId>, Vec<libp2p::Multiaddr>) {
        let keypairs = (0..n).map(|_| EdKeypair::generate()).collect::<Vec<_>>();
        let peer_ids = keypairs
            .iter()
            .map(|key| PeerId::from_public_key(&Keypair::from(key.clone()).public()))
            .collect::<Vec<_>>();
        let multiaddresses = (1..(keypairs.len() + 1) as u16)
            .map(|idx| build_multiaddr!(Memory(idx)))
            .collect::<Vec<_>>();
        (keypairs, peer_ids, multiaddresses)
    }

    /// Wait until all operators established connections with other operators,
    /// and then spawn [`P2P::listen`]s in separate tasks using [`TaskTracker`].
    async fn start_operators(mut operators: Vec<Operator>) -> (Vec<OperatorHandle>, TaskTracker) {
        // wait until all of them established connections and subscriptions
        join_all(
            operators
                .iter_mut()
                .map(|op| op.p2p.establish_connections())
                .collect::<Vec<_>>(),
        )
        .await;

        let mut levers = Vec::new();
        let tasks = TaskTracker::new();
        for operator in operators {
            let peer_id = operator.p2p.local_peer_id();
            tasks.spawn(operator.p2p.listen());

            levers.push(OperatorHandle {
                gossip_handle: operator.gossip_handle,
                req_resp_handle: operator.req_resp_handle,
                peer_id,
                kp: operator.kp,
            });
        }

        tasks.close();
        (levers, tasks)
    }
}

pub(crate) fn mock_stake_chain_info(
    kp: &EdKeypair,
    stake_chain_id: StakeChainId,
) -> PublishMessage {
    let kind = UnsignedPublishMessage::StakeChainExchange {
        stake_chain_id,
        // some random point
        operator_pk: XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
        pre_stake_txid: Txid::all_zeros(),
        pre_stake_vout: 0,
    };
    kind.sign_ed25519(kp)
}

pub(crate) fn mock_deposit_setup(kp: &EdKeypair, scope: Scope) -> PublishMessage {
    let mock_bytes = [0u8; 1_360 + 362_960];
    let mock_index = 0;
    let unsigned = UnsignedPublishMessage::DepositSetup {
        index: mock_index,
        scope,
        hash: sha256::Hash::const_hash(b"hash me!"),
        funding_txid: Txid::all_zeros(),
        funding_vout: 0,
        operator_pk: XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap(),
        wots_pks: WotsPublicKeys::from_flattened_bytes(&mock_bytes),
    };
    unsigned.sign_ed25519(kp)
}

pub(crate) fn mock_deposit_nonces(kp: &EdKeypair, session_id: SessionId) -> PublishMessage {
    let unsigned = UnsignedPublishMessage::Musig2NoncesExchange {
        session_id,
        pub_nonces: (0..5).map(|_| generate_pubnonce()).collect(),
    };
    unsigned.sign_ed25519(kp)
}

pub(crate) fn mock_deposit_sigs(kp: &EdKeypair, session_id: SessionId) -> PublishMessage {
    let unsigned = UnsignedPublishMessage::Musig2SignaturesExchange {
        session_id,
        partial_sigs: (0..5).map(|_| generate_partial_signature()).collect(),
    };
    unsigned.sign_ed25519(kp)
}

pub(crate) async fn exchange_stake_chain_info(
    operators: &mut [OperatorHandle],
    operators_num: usize,
    stake_chain_id: StakeChainId,
) -> anyhow::Result<()> {
    for operator in operators.iter_mut() {
        let msg = mock_stake_chain_info(&operator.kp, stake_chain_id);
        let msg = GossipsubMsg::from(msg);
        let mut data = Vec::new();
        rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&msg, &mut data)
            .expect("must be able to serialize msg");
        operator.gossip_handle.send(GossipCommand { data }).await?;
    }
    for operator in operators.iter_mut() {
        // received stake chain info from other n-1 operators
        for _ in 0..operators_num - 1 {
            let GossipEvent::ReceivedMessage(raw_msg) = operator.gossip_handle.next_event().await?;
            let archived = rkyv::access::<ArchivedGossipsubMsg, rkyv::rancor::Error>(&raw_msg)
                .expect("must be able to deserialize msg");
            let msg = rkyv::deserialize::<GossipsubMsg, rkyv::rancor::Error>(archived)
                .expect("must be able to deserialize msg");

            if !matches!(
                msg,
                GossipsubMsg {
                    unsigned: UnsignedGossipsubMsg::StakeChainExchange { .. },
                    ..
                }
            ) {
                bail!("Got event other than 'stake_chain_info' - {:?}", msg);
            }
        }

        assert!(operator.gossip_handle.events_is_empty());
    }

    Ok(())
}

pub(crate) async fn exchange_deposit_setup(
    operators: &mut [OperatorHandle],
    operators_num: usize,
    scope: Scope,
) -> anyhow::Result<()> {
    for operator in operators.iter_mut() {
        let msg = mock_deposit_setup(&operator.kp, scope);
        let msg = GossipsubMsg::from(msg);
        let mut data = Vec::new();
        rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&msg, &mut data)
            .expect("must be able to serialize msg");
        operator.gossip_handle.send(GossipCommand { data }).await?;
    }
    for operator in operators.iter_mut() {
        for _ in 0..operators_num - 1 {
            let GossipEvent::ReceivedMessage(raw_msg) =
                operator.gossip_handle.next_event().await.unwrap();
            let archived = rkyv::access::<ArchivedGossipsubMsg, rkyv::rancor::Error>(&raw_msg)
                .expect("must be able to deserialize msg");
            let msg = rkyv::deserialize::<GossipsubMsg, rkyv::rancor::Error>(archived)
                .expect("must be able to deserialize msg");
            if !matches!(
                msg,
                GossipsubMsg {
                    unsigned: UnsignedGossipsubMsg::DepositSetup { .. },
                    ..
                }
            ) {
                bail!("Got event other than 'deposit_setup' - {:?}", msg);
            }
            info!(to=%operator.peer_id, "Got deposit setup");
        }
        assert!(operator.gossip_handle.events_is_empty());
    }
    Ok(())
}

pub(crate) async fn exchange_deposit_nonces(
    operators: &mut [OperatorHandle],
    operators_num: usize,
    session_id: SessionId,
) -> anyhow::Result<()> {
    for operator in operators.iter_mut() {
        let msg = mock_deposit_nonces(&operator.kp, session_id);
        let msg = GossipsubMsg::from(msg);
        let mut data = Vec::new();
        rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&msg, &mut data)
            .expect("must be able to serialize msg");
        operator.gossip_handle.send(GossipCommand { data }).await?;
    }
    for operator in operators.iter_mut() {
        for _ in 0..operators_num - 1 {
            let GossipEvent::ReceivedMessage(raw_msg) =
                operator.gossip_handle.next_event().await.unwrap();
            let archived = rkyv::access::<ArchivedGossipsubMsg, rkyv::rancor::Error>(&raw_msg)
                .expect("must be able to deserialize msg");
            let msg = rkyv::deserialize::<GossipsubMsg, rkyv::rancor::Error>(archived)
                .expect("must be able to deserialize msg");
            if !matches!(
                msg,
                GossipsubMsg {
                    unsigned: UnsignedGossipsubMsg::Musig2NoncesExchange { .. },
                    ..
                }
            ) {
                bail!("Got event other than 'deposit_nonces' - {:?}", msg);
            }
            info!(to=%operator.peer_id, "Got deposit setup");
        }
        assert!(operator.gossip_handle.events_is_empty());
    }
    Ok(())
}

pub(crate) async fn exchange_deposit_sigs(
    operators: &mut [OperatorHandle],
    operators_num: usize,
    session_id: SessionId,
) -> anyhow::Result<()> {
    for operator in operators.iter_mut() {
        let msg = mock_deposit_sigs(&operator.kp, session_id);
        let msg = GossipsubMsg::from(msg);
        let mut data = Vec::new();
        rkyv::api::high::to_bytes_in::<_, rkyv::rancor::Error>(&msg, &mut data)
            .expect("must be able to serialize msg");
        operator.gossip_handle.send(GossipCommand { data }).await?;
    }

    for operator in operators.iter_mut() {
        for _ in 0..operators_num - 1 {
            let GossipEvent::ReceivedMessage(raw_msg) =
                operator.gossip_handle.next_event().await.unwrap();
            let archived = rkyv::access::<ArchivedGossipsubMsg, rkyv::rancor::Error>(&raw_msg)
                .expect("must be able to deserialize msg");
            let msg = rkyv::deserialize::<GossipsubMsg, rkyv::rancor::Error>(archived)
                .expect("must be able to deserialize msg");
            if !matches!(
                msg,
                GossipsubMsg {
                    unsigned: UnsignedGossipsubMsg::Musig2SignaturesExchange { .. },
                    ..
                }
            ) {
                bail!("Got event other than 'deposit_sigs' - {:?}", msg);
            }
            info!(to=%operator.peer_id, "Got deposit sigs");
        }
        assert!(operator.gossip_handle.events_is_empty());
    }

    Ok(())
}
