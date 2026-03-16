//! Provides p2p handles initialization.

use anyhow::anyhow;
use ed25519_dalek::SigningKey;
use libp2p::PeerId;
use libp2p_identity::{
    PublicKey as LibP2pPublicKey,
    ed25519::{Keypair, PublicKey as LibP2pEdPublicKey},
};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{P2PSigner, SecretService};
use strata_bridge_p2p_service::{Configuration as P2PConfiguration, bootstrap as p2p_bootstrap};
use strata_bridge_primitives::types::P2POperatorPubKey;
use strata_p2p::swarm::handle::{CommandHandle, GossipHandle, ReqRespHandle};
use strata_tasks::TaskExecutor;
use tracing::{debug, info};

use crate::{
    config::{Config, P2PConfig},
    params::Params,
};

/// Results of initializing the P2P system.
#[derive(Debug)]
pub(in crate::mode) struct P2PHandles {
    /// Handle to send commands to the P2P swarm.
    pub(in crate::mode) command_handle: CommandHandle,
    /// Handle to the gossip subsystem.
    pub(in crate::mode) gossip_handle: GossipHandle,
    /// Handle to the request-response subsystem.
    pub(in crate::mode) req_resp_handle: ReqRespHandle,
    /// [`Keypair`] used as [`PeerId`].
    pub(in crate::mode) keypair: Keypair,
}

/// Initializes the p2p handles based on the provided configuration and parameters.
pub(in crate::mode) async fn init_p2p_handles(
    config: &Config,
    params: &Params,
    s2_client: &SecretServiceClient,
    executor: &TaskExecutor,
) -> anyhow::Result<P2PHandles> {
    let p2p_sk = s2_client
        .p2p_signer()
        .secret_key()
        .await
        .map_err(|e| anyhow!("could not fetch p2p secret key from s2 due to {e:?}"))?;

    let pubkey =
        SigningKey::from_bytes(p2p_sk.as_ref().try_into().expect("private key is 32 bytes"))
            .verifying_key()
            .to_bytes();
    let my_key = LibP2pEdPublicKey::try_from_bytes(&pubkey).expect("infallible");
    let other_operators: Vec<LibP2pEdPublicKey> = params
        .keys
        .covenant
        .iter()
        .filter(|&cov| cov.p2p != my_key)
        .map(|cov| cov.p2p.clone())
        .collect();

    let allowlist: Vec<PeerId> = other_operators
        .clone()
        .into_iter()
        .map(|pk| {
            let pk: LibP2pPublicKey = pk.into();
            PeerId::from(pk)
        })
        .collect();
    let signers_allowlist: Vec<P2POperatorPubKey> =
        other_operators.into_iter().map(Into::into).collect();

    let P2PConfig {
        idle_connection_timeout,
        listening_addr,
        connect_to,
        num_threads,
        dial_timeout,
        general_timeout,
        connection_check_interval,
        gossipsub_mesh_n,
        gossipsub_mesh_n_low,
        gossipsub_mesh_n_high,
        gossipsub_scoring_preset,
        gossipsub_heartbeat_initial_delay,
        gossipsub_publish_queue_duration,
        gossipsub_forward_queue_duration,
    } = config.p2p.clone();

    let config = P2PConfiguration::new_with_secret_key(
        p2p_sk,
        idle_connection_timeout,
        listening_addr,
        allowlist,
        connect_to,
        signers_allowlist,
        num_threads,
        dial_timeout,
        general_timeout,
        connection_check_interval,
        gossipsub_mesh_n,
        gossipsub_mesh_n_low,
        gossipsub_mesh_n_high,
        gossipsub_scoring_preset,
        gossipsub_heartbeat_initial_delay,
        gossipsub_publish_queue_duration,
        gossipsub_forward_queue_duration,
    );
    let handles = p2p_bootstrap(&config).await?;

    let listen_task = handles.listen_task;

    debug!(p2p_key=?pubkey, "starting p2p listener service");
    executor.spawn_critical_async_with_shutdown("p2p_listener", |_| async move {
        listen_task.await.map_err(anyhow::Error::from)
    });
    info!("p2p listener service started successfully");

    Ok(P2PHandles {
        command_handle: handles.command_handle,
        gossip_handle: handles.gossip_handle,
        req_resp_handle: handles.req_resp_handle,
        keypair: config.keypair,
    })
}
