//! Helper functions for the P2P tests.

use std::time::Duration;

use anyhow::bail;
use libp2p::{
    build_multiaddr,
    identity::{ed25519::Keypair as EdKeypair, Keypair},
    Multiaddr, PeerId,
};
use strata_bridge_p2p_types::{GossipsubMsg, UnsignedGossipsubMsg};
use strata_p2p::{
    events::GossipEvent,
    swarm::{
        self,
        handle::{GossipHandle, ReqRespHandle},
        P2PConfig, P2P,
    },
};
use tokio::sync::mpsc;
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{info, trace};

use crate::message_handler::{MessageHandler, OuroborosMessage};

pub(crate) struct Operator {
    pub(crate) p2p: P2P,
    pub(crate) gossip_handle: GossipHandle,
    pub(crate) req_resp_handle: ReqRespHandle,
    pub(crate) kp: EdKeypair,
}

const HEARTBEAT_INITIAL_DELAY: Duration = Duration::from_secs(5);

impl Operator {
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn new(
        keypair: EdKeypair,
        connect_to: Vec<Multiaddr>,
        local_addr: Multiaddr,
        cancel: CancellationToken,
        dial_timeout: Option<Duration>,
        general_timeout: Option<Duration>,
        connection_check_interval: Option<Duration>,
        heartbeat_initial_delay: Option<Duration>,
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
            gossipsub_mesh_n: None,
            gossipsub_mesh_n_low: None,
            gossipsub_mesh_n_high: None,
            gossipsub_heartbeat_initial_delay: heartbeat_initial_delay,
            gossipsub_forward_queue_duration: None,
            gossipsub_publish_queue_duration: None,
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
    pub(crate) handler: MessageHandler,
    pub(crate) ouroboros_rx: mpsc::UnboundedReceiver<OuroborosMessage>,
    pub(crate) gossip_handle: GossipHandle,
    #[expect(dead_code)]
    pub(crate) req_resp_handle: ReqRespHandle,
    pub(crate) peer_id: PeerId,
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

            let operator = Operator::new(
                keypair.clone(),
                other_addrs,
                addr.clone(),
                cancel.child_token(),
                Some(Duration::from_millis(250)),
                Some(Duration::from_millis(250)),
                Some(Duration::from_millis(500)),
                Some(HEARTBEAT_INITIAL_DELAY),
            )?;

            operators.push(operator);
        }

        let (operators, tasks) = Self::start_operators(operators).await;

        // Wait for gossipsub mesh to stabilize.
        // Adding 1 extra second for safety margin.
        info!("Waiting for gossipsub mesh to stabilize...");
        tokio::time::sleep(HEARTBEAT_INITIAL_DELAY + Duration::from_secs(1)).await;
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
        futures::future::join_all(
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

            let (ouroboros_tx, ouroboros_rx) = mpsc::unbounded_channel();
            let handler =
                MessageHandler::new(ouroboros_tx, operator.gossip_handle.clone(), operator.kp);

            levers.push(OperatorHandle {
                handler,
                ouroboros_rx,
                gossip_handle: operator.gossip_handle,
                req_resp_handle: operator.req_resp_handle,
                peer_id,
            });
        }

        tasks.close();
        (levers, tasks)
    }
}

/// Verifies that each operator's ouroboros channel received a message matching the predicate,
/// and that all other operators received the gossip broadcast.
pub(crate) async fn verify_dispatch(
    operators: &mut [OperatorHandle],
    operators_num: usize,
    expected_variant: &str,
    match_ouroboros: impl Fn(&UnsignedGossipsubMsg) -> bool,
) -> anyhow::Result<()> {
    // Each operator should have received the unsigned msg on the ouroboros channel
    for operator in operators.iter_mut() {
        let ouroboros_msg = operator
            .ouroboros_rx
            .try_recv()
            .expect("ouroboros channel should have a message");
        if !match_ouroboros(&ouroboros_msg.publish) {
            bail!(
                "operator {} ouroboros message doesn't match expected {expected_variant}",
                operator.peer_id
            );
        }
    }

    // Each operator should receive broadcasts from all other operators
    for operator in operators.iter_mut() {
        for _ in 0..operators_num - 1 {
            let GossipEvent::ReceivedMessage(raw_msg) = operator.gossip_handle.next_event().await?;
            let archived =
                rkyv::access::<rkyv::Archived<GossipsubMsg>, rkyv::rancor::Error>(&raw_msg)
                    .expect("must be able to access archived msg");
            let _msg = rkyv::deserialize::<GossipsubMsg, rkyv::rancor::Error>(archived)
                .expect("must be able to deserialize msg");
        }

        if !operator.gossip_handle.events_is_empty() {
            bail!(
                "operator {} has unexpected extra gossip events after {expected_variant}",
                operator.peer_id
            );
        }
    }

    Ok(())
}
