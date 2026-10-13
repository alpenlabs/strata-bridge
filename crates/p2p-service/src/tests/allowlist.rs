use std::{collections::BTreeMap, net::TcpListener as StdTcpListener, time::Duration};

use libp2p::{
    identity::{ed25519::Keypair as EdKeypair, Keypair},
    Multiaddr, PeerId,
};
use strata_bridge_common::logging;
use strata_p2p::{
    commands::{Command, QueryP2PStateCommand},
    swarm::handle::CommandHandle,
};
use tokio::{sync::oneshot, task::yield_now, time::timeout};

use crate::{
    bootstrap::{bootstrap, BootstrapHandles},
    Configuration,
};

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(1);

fn build_config(keypair: EdKeypair, allowlist: Vec<PeerId>) -> Configuration {
    build_config_with_addresses(keypair, allowlist, BTreeMap::new())
}

fn build_config_with_addresses(
    keypair: EdKeypair,
    allowlist: Vec<PeerId>,
    peer_addresses: BTreeMap<PeerId, Vec<Multiaddr>>,
) -> Configuration {
    Configuration {
        keypair,
        idle_connection_timeout: None,
        listening_addr: "/ip4/127.0.0.1/tcp/0".parse().expect("valid addr"),
        allowlist,
        peer_addresses,
        signers_allowlist: vec![],
        num_threads: None,
        dial_timeout: Some(Duration::from_millis(250)),
        general_timeout: Some(Duration::from_millis(250)),
        connection_check_interval: Some(Duration::from_millis(500)),
        gossipsub_mesh_n: None,
        gossipsub_mesh_n_low: None,
        gossipsub_mesh_n_high: None,
        gossipsub_scoring_preset: None,
        gossipsub_heartbeat_initial_delay: None,
        gossipsub_publish_queue_duration: None,
        gossipsub_forward_queue_duration: None,
        peer_reconnect_interval: None,
        rate_limit_message_cost: None,
        rate_limit_mute_threshold: None,
        rate_limit_recovery_per_sec: None,
        rate_limit_mute_duration: None,
        gossip_event_buffer_size: None,
        gossip_command_buffer_size: None,
    }
}

async fn listening_addrs(command_handle: &CommandHandle) -> anyhow::Result<Vec<Multiaddr>> {
    let (sender, receiver) = oneshot::channel();
    command_handle
        .send_command(Command::QueryP2PState(
            QueryP2PStateCommand::GetMyListeningAddresses {
                response_sender: sender,
            },
        ))
        .await;

    Ok(receiver.await?)
}

async fn shutdown(handles: BootstrapHandles) -> anyhow::Result<()> {
    handles.cancel.cancel();
    handles.listen_task.await?;
    Ok(())
}

fn peer_id(keypair: &EdKeypair) -> PeerId {
    PeerId::from_public_key(&Keypair::from(keypair.clone()).public())
}

async fn connects_within(
    command_handle: &CommandHandle,
    peer_id: PeerId,
    timeout_after: Duration,
) -> bool {
    timeout(timeout_after, async {
        loop {
            if command_handle
                .is_connected(&peer_id, Some(Duration::from_millis(50)))
                .await
            {
                return;
            }

            yield_now().await;
        }
    })
    .await
    .is_ok()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_enforces_transport_allowlist() -> anyhow::Result<()> {
    logging::init_from_env("p2p-test-bootstrap-transport-allowlist");

    let victim_keypair = EdKeypair::generate();
    let attacker_keypair = EdKeypair::generate();
    let victim_peer_id = PeerId::from_public_key(&Keypair::from(victim_keypair.clone()).public());
    let attacker_peer_id =
        PeerId::from_public_key(&Keypair::from(attacker_keypair.clone()).public());

    let victim_handles = bootstrap(&build_config(victim_keypair, vec![])).await?;
    let attacker_handles = bootstrap(&build_config(attacker_keypair, vec![victim_peer_id])).await?;

    let victim_addrs = listening_addrs(&victim_handles.command_handle).await?;

    attacker_handles
        .command_handle
        .send_command(Command::ConnectToPeer {
            transport_id: victim_peer_id,
            addresses: victim_addrs,
        })
        .await;

    let victim_connected = connects_within(
        &victim_handles.command_handle,
        attacker_peer_id,
        CONNECTION_TIMEOUT,
    )
    .await;
    let attacker_connected = connects_within(
        &attacker_handles.command_handle,
        victim_peer_id,
        CONNECTION_TIMEOUT,
    )
    .await;

    assert!(!victim_connected);
    assert!(!attacker_connected);
    assert!(victim_handles
        .command_handle
        .get_connected_peers(None)
        .await
        .is_empty());
    assert!(attacker_handles
        .command_handle
        .get_connected_peers(None)
        .await
        .is_empty());

    shutdown(attacker_handles).await?;
    shutdown(victim_handles).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_dials_peers_at_their_keyed_addresses() -> anyhow::Result<()> {
    logging::init_from_env("p2p-test-bootstrap-keyed-addresses");

    let dialer_keypair = EdKeypair::generate();
    let listener_keypair = EdKeypair::generate();
    let dialer_peer_id = peer_id(&dialer_keypair);
    let listener_peer_id = peer_id(&listener_keypair);

    let listener_handles = bootstrap(&build_config(listener_keypair, vec![dialer_peer_id])).await?;
    let listener_addrs = listening_addrs(&listener_handles.command_handle).await?;

    let dialer_handles = bootstrap(&build_config_with_addresses(
        dialer_keypair,
        vec![listener_peer_id],
        BTreeMap::from([(listener_peer_id, listener_addrs)]),
    ))
    .await?;

    assert!(
        connects_within(
            &dialer_handles.command_handle,
            listener_peer_id,
            CONNECTION_TIMEOUT,
        )
        .await,
        "the dialer must connect to the peer at the address configured for it"
    );

    shutdown(dialer_handles).await?;
    shutdown(listener_handles).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reconnect_dials_every_address_of_a_peer_that_comes_online_later() -> anyhow::Result<()> {
    logging::init_from_env("p2p-test-reconnect-keyed-addresses");

    let dialer_keypair = EdKeypair::generate();
    let listener_keypair = EdKeypair::generate();
    let dialer_peer_id = peer_id(&dialer_keypair);
    let listener_peer_id = peer_id(&listener_keypair);

    let listener_port = StdTcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
    let listener_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{listener_port}").parse()?;
    let unreachable_addr: Multiaddr = "/ip4/127.0.0.1/tcp/1".parse()?;

    let mut dialer_config = build_config_with_addresses(
        dialer_keypair,
        vec![listener_peer_id],
        BTreeMap::from([(
            listener_peer_id,
            vec![unreachable_addr, listener_addr.clone()],
        )]),
    );
    dialer_config.peer_reconnect_interval = Some(Duration::from_millis(200));
    let dialer_handles = bootstrap(&dialer_config).await?;

    let mut listener_config = build_config(listener_keypair, vec![dialer_peer_id]);
    listener_config.listening_addr = listener_addr;
    let listener_handles = bootstrap(&listener_config).await?;

    assert!(
        connects_within(
            &dialer_handles.command_handle,
            listener_peer_id,
            Duration::from_secs(3),
        )
        .await,
        "the reconnect task must reach the peer through its second, reachable address"
    );

    shutdown(dialer_handles).await?;
    shutdown(listener_handles).await?;

    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_rejects_addresses_for_peers_outside_the_allowlist() {
    logging::init_from_env("p2p-test-bootstrap-unknown-peer-address");

    let keypair = EdKeypair::generate();
    let stranger_peer_id = peer_id(&EdKeypair::generate());

    let result = bootstrap(&build_config_with_addresses(
        keypair,
        vec![],
        BTreeMap::from([(
            stranger_peer_id,
            vec!["/ip4/127.0.0.1/tcp/1".parse().expect("valid addr")],
        )]),
    ))
    .await;

    assert!(
        result.is_err(),
        "an address for a peer outside the allowlist must fail bootstrap"
    );
}
