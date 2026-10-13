//! Provides p2p handles initialization.

use anyhow::anyhow;
use ed25519_dalek::SigningKey;
use libp2p::PeerId;
use libp2p_identity::{
    DecodingError, PublicKey as LibP2pPublicKey,
    ed25519::{Keypair, PublicKey as LibP2pEdPublicKey},
};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{P2PSigner, SecretService};
use strata_bridge_common::params::Params;
use strata_bridge_p2p_service::{Configuration as P2PConfiguration, bootstrap as p2p_bootstrap};
use strata_bridge_primitives::types::P2POperatorPubKey;
use strata_p2p::swarm::handle::{CommandHandle, GossipHandle, ReqRespHandle};
use strata_tasks::TaskExecutor;
use tracing::{debug, info};

use crate::config::{Config, P2PConfig};

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
    let other_operators: Vec<(P2POperatorPubKey, PeerId)> = params
        .keys
        .operators
        .iter()
        .filter(|operator| operator.p2p_key().as_ref() != my_key.to_bytes().as_slice())
        .map(|operator| {
            let peer_id = peer_id_from_p2p_key(operator.p2p_key()).map_err(|_| {
                anyhow!(
                    "invalid p2p key for scheduled operator {}",
                    operator.index()
                )
            })?;
            Ok((operator.p2p_key().clone(), peer_id))
        })
        .collect::<anyhow::Result<_>>()?;

    let allowlist: Vec<PeerId> = other_operators
        .iter()
        .map(|(_, peer_id)| *peer_id)
        .collect();
    let signers_allowlist: Vec<P2POperatorPubKey> = other_operators
        .into_iter()
        .map(|(p2p_key, _)| p2p_key)
        .collect();

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
        peer_reconnect_interval,
        rate_limit_message_cost,
        rate_limit_mute_threshold,
        rate_limit_recovery_per_sec,
        rate_limit_mute_duration,
        gossip_event_buffer_size,
        gossip_command_buffer_size,
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
        peer_reconnect_interval,
        rate_limit_message_cost,
        rate_limit_mute_threshold,
        rate_limit_recovery_per_sec,
        rate_limit_mute_duration,
        gossip_event_buffer_size,
        gossip_command_buffer_size,
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

/// Derives the [`PeerId`] that libp2p authenticates an operator's P2P key as.
///
/// Fails if the key is not a valid ed25519 public key.
pub(in crate::mode) fn peer_id_from_p2p_key(
    p2p_key: &P2POperatorPubKey,
) -> Result<PeerId, DecodingError> {
    let ed_key = LibP2pEdPublicKey::try_from_bytes(p2p_key.as_ref())?;
    Ok(PeerId::from(LibP2pPublicKey::from(ed_key)))
}

#[cfg(test)]
mod tests {
    use libp2p_identity::Keypair as LibP2pKeypair;

    use super::*;

    #[test]
    fn peer_id_matches_the_libp2p_identity_of_the_p2p_key() {
        let keypair = LibP2pKeypair::generate_ed25519();
        let ed_public = keypair
            .public()
            .try_into_ed25519()
            .expect("generated keypair is ed25519");
        let p2p_key = P2POperatorPubKey::from(ed_public.to_bytes().to_vec());

        assert_eq!(
            peer_id_from_p2p_key(&p2p_key).expect("valid ed25519 key"),
            keypair.public().to_peer_id(),
            "the derived peer ID must be the one libp2p authenticates the key as"
        );
    }

    #[test]
    fn peer_id_rejects_keys_that_are_not_ed25519() {
        let p2p_key = P2POperatorPubKey::from(vec![0xAB; 31]);

        assert!(
            peer_id_from_p2p_key(&p2p_key).is_err(),
            "a 31-byte key cannot be an ed25519 public key"
        );
    }
}
