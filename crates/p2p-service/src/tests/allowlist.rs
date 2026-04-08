use std::time::Duration;

use libp2p::{
    identity::{ed25519::Keypair as EdKeypair, Keypair},
    Multiaddr, PeerId,
};
use strata_bridge_common::logging::{self, LoggerConfig};
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
    Configuration {
        keypair,
        idle_connection_timeout: None,
        listening_addr: "/ip4/127.0.0.1/tcp/0".parse().expect("valid addr"),
        allowlist,
        connect_to: vec![],
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
    logging::init(LoggerConfig::new(
        "p2p-test-bootstrap-transport-allowlist".to_string(),
    ));

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
