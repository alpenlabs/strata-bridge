//! Provides p2p handles initialization.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{anyhow, bail};
use ed25519_dalek::SigningKey;
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use libp2p_identity::{
    DecodingError, PublicKey as LibP2pPublicKey,
    ed25519::{Keypair, PublicKey as LibP2pEdPublicKey},
};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{P2PSigner, SecretService};
use strata_bridge_common::params::Params;
use strata_bridge_p2p_service::{Configuration as P2PConfiguration, bootstrap as p2p_bootstrap};
use strata_bridge_primitives::{
    operator_set_schedule::OperatorSetSchedule,
    types::{OperatorIdx, P2POperatorPubKey},
};
use strata_p2p::swarm::handle::{CommandHandle, GossipHandle, ReqRespHandle};
use strata_tasks::TaskExecutor;
use tracing::{debug, info};

use crate::config::{Config, P2PConfig, P2PPeerConfig};

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
        peers,
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

    let own_p2p_key = P2POperatorPubKey::from(pubkey.to_vec());
    let peer_addresses = resolve_peer_addresses(&peers, &params.keys.operators, &own_p2p_key)?;

    let config = P2PConfiguration::new_with_secret_key(
        p2p_sk,
        idle_connection_timeout,
        listening_addr,
        allowlist,
        peer_addresses,
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

/// Resolves configured peer entries into the addresses to dial for each peer identity.
///
/// Fails if an entry names an unregistered operator or this node, repeats an operator, lists no
/// addresses, shares an address with another operator, or carries a `/p2p/` suffix naming an
/// identity other than the operator's params P2P key.
fn resolve_peer_addresses(
    peers: &[P2PPeerConfig],
    operators: &OperatorSetSchedule,
    own_p2p_key: &P2POperatorPubKey,
) -> anyhow::Result<BTreeMap<PeerId, Vec<Multiaddr>>> {
    let mut resolved = BTreeMap::new();
    let mut configured_operators = BTreeSet::new();
    let mut address_owners: HashMap<Multiaddr, OperatorIdx> = HashMap::new();

    for P2PPeerConfig {
        operator_idx,
        addrs,
    } in peers
    {
        let operator_idx = *operator_idx;
        let operator = operators.get(operator_idx).ok_or_else(|| {
            anyhow!(
                "p2p peer entry names operator {operator_idx}, which is not registered in params"
            )
        })?;
        if operator.p2p_key() == own_p2p_key {
            bail!("p2p peer entry for operator {operator_idx} names this node");
        }
        if !configured_operators.insert(operator_idx) {
            bail!("p2p peers list operator {operator_idx} more than once");
        }
        if addrs.is_empty() {
            bail!("p2p peer entry for operator {operator_idx} lists no addresses");
        }

        let peer_id = peer_id_from_p2p_key(operator.p2p_key())
            .map_err(|_| anyhow!("invalid p2p key for scheduled operator {operator_idx}"))?;
        for addr in addrs {
            if let Some(named) = named_peer_id(addr)
                && named != peer_id
            {
                bail!(
                    "address {addr} for operator {operator_idx} names peer {named}, but operator \
                     {operator_idx} is peer {peer_id}"
                );
            }
            let transport_addr = without_peer_id(addr);
            if let Some(owner) = address_owners.insert(transport_addr.clone(), operator_idx)
                && owner != operator_idx
            {
                let (first, second) = (owner.min(operator_idx), owner.max(operator_idx));
                bail!("address {transport_addr} is configured for operators {first} and {second}");
            }
        }

        resolved.insert(peer_id, addrs.clone());
    }

    Ok(resolved)
}

/// Returns the peer identity named by a trailing `/p2p/<peer-id>` component, if any.
fn named_peer_id(addr: &Multiaddr) -> Option<PeerId> {
    addr.iter().find_map(|protocol| match protocol {
        Protocol::P2p(peer_id) => Some(peer_id),
        _ => None,
    })
}

/// Strips any `/p2p/<peer-id>` component, leaving the address that is actually dialed.
fn without_peer_id(addr: &Multiaddr) -> Multiaddr {
    addr.iter()
        .filter(|protocol| !matches!(protocol, Protocol::P2p(_)))
        .collect()
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
    use crate::mode::services::test_fixtures::test_params;

    fn peer(operator_idx: OperatorIdx, addrs: &[&str]) -> P2PPeerConfig {
        P2PPeerConfig {
            operator_idx,
            addrs: addrs
                .iter()
                .map(|addr| addr.parse().expect("valid multiaddr"))
                .collect(),
        }
    }

    fn registered_peer_id(operator_idx: OperatorIdx) -> PeerId {
        let params = test_params();
        let operator = params
            .keys
            .operators
            .get(operator_idx)
            .expect("operator is registered");
        peer_id_from_p2p_key(operator.p2p_key()).expect("valid p2p key")
    }

    fn own_key(operator_idx: OperatorIdx) -> P2POperatorPubKey {
        test_params()
            .keys
            .operators
            .get(operator_idx)
            .expect("operator is registered")
            .p2p_key()
            .clone()
    }

    fn observer_key() -> P2POperatorPubKey {
        let keypair = LibP2pKeypair::generate_ed25519();
        let ed_public = keypair
            .public()
            .try_into_ed25519()
            .expect("generated keypair is ed25519");
        P2POperatorPubKey::from(ed_public.to_bytes().to_vec())
    }

    fn resolve_err(peers: &[P2PPeerConfig], own: &P2POperatorPubKey) -> String {
        resolve_peer_addresses(peers, &test_params().keys.operators, own)
            .expect_err("the peer configuration is invalid")
            .to_string()
    }

    #[test]
    fn peer_addresses_follow_operator_indices_not_entry_order() {
        let params = test_params();
        let own = observer_key();
        let in_order = [
            peer(0, &["/ip4/10.0.0.1/tcp/5679"]),
            peer(1, &["/ip4/10.0.0.2/tcp/5679"]),
        ];
        let reversed = [in_order[1].clone(), in_order[0].clone()];

        let resolved = resolve_peer_addresses(&in_order, &params.keys.operators, &own)
            .expect("valid peer configuration");

        assert_eq!(
            resolved,
            resolve_peer_addresses(&reversed, &params.keys.operators, &own)
                .expect("valid peer configuration"),
            "reordering peer entries must not change which peer owns which address"
        );
        assert_eq!(
            resolved.get(&registered_peer_id(1)),
            Some(&vec![
                "/ip4/10.0.0.2/tcp/5679".parse().expect("valid multiaddr")
            ]),
            "operator 1's address must belong to operator 1's params identity"
        );
    }

    #[test]
    fn registrations_without_addresses_are_not_dialed() {
        let params = test_params();

        let resolved = resolve_peer_addresses(
            &[peer(1, &["/ip4/10.0.0.2/tcp/5679"])],
            &params.keys.operators,
            &observer_key(),
        )
        .expect("valid peer configuration");

        assert_eq!(
            resolved.keys().copied().collect::<Vec<_>>(),
            vec![registered_peer_id(1)],
            "only operators with configured addresses are dialed"
        );
    }

    #[test]
    fn peer_addresses_accept_a_matching_peer_id_suffix() {
        let params = test_params();
        let addr = format!("/ip4/10.0.0.2/tcp/5679/p2p/{}", registered_peer_id(1));

        let resolved =
            resolve_peer_addresses(&[peer(1, &[&addr])], &params.keys.operators, &own_key(0))
                .expect("a suffix naming the operator's own identity is valid");

        assert_eq!(
            resolved.len(),
            1,
            "the suffixed address must be kept for operator 1"
        );
    }

    #[test]
    fn peer_addresses_reject_unknown_operators() {
        let err = resolve_err(&[peer(7, &["/ip4/10.0.0.7/tcp/5679"])], &own_key(0));

        assert!(
            err.contains("operator 7") && err.contains("not registered"),
            "an index without a params registration must be named: {err}"
        );
    }

    #[test]
    fn peer_addresses_reject_this_node() {
        let err = resolve_err(&[peer(0, &["/ip4/10.0.0.1/tcp/5679"])], &own_key(0));

        assert!(
            err.contains("operator 0") && err.contains("this node"),
            "an entry for this node's own registration must be rejected: {err}"
        );
    }

    #[test]
    fn peer_addresses_reject_duplicate_operators() {
        let err = resolve_err(
            &[
                peer(1, &["/ip4/10.0.0.2/tcp/5679"]),
                peer(1, &["/ip4/10.0.0.3/tcp/5679"]),
            ],
            &own_key(0),
        );

        assert!(
            err.contains("operator 1") && err.contains("more than once"),
            "a repeated index must be rejected: {err}"
        );
    }

    #[test]
    fn peer_addresses_reject_entries_without_addresses() {
        let err = resolve_err(&[peer(1, &[])], &own_key(0));

        assert!(
            err.contains("operator 1") && err.contains("no addresses"),
            "an entry without addresses must be rejected: {err}"
        );
    }

    #[test]
    fn peer_addresses_reject_addresses_shared_by_operators() {
        let addr = "/ip4/10.0.0.2/tcp/5679";
        let suffixed = format!("{addr}/p2p/{}", registered_peer_id(1));

        let err = resolve_err(&[peer(0, &[addr]), peer(1, &[&suffixed])], &observer_key());

        assert!(
            err.contains(addr) && err.contains("operators 0 and 1"),
            "an address claimed by two operators is ambiguous: {err}"
        );
    }

    #[test]
    fn peer_addresses_reject_a_mismatched_peer_id_suffix() {
        let addr = format!("/ip4/10.0.0.2/tcp/5679/p2p/{}", registered_peer_id(0));

        let err = resolve_err(&[peer(1, &[&addr])], &observer_key());

        assert!(
            err.contains("operator 1") && err.contains(&registered_peer_id(0).to_string()),
            "a suffix naming another identity must be rejected: {err}"
        );
    }

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
