//! Strata Bridge P2P.

pub mod bootstrap;
pub mod config;
pub mod constants;
pub mod message_handler;

#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use bitcoin::{key::Parity, secp256k1::SecretKey, XOnlyPublicKey};
    use libp2p::{Multiaddr, PeerId};
    // Oh my this is annoying...
    use libp2p_identity::{
        secp256k1::{
            Keypair as Libp2pSecpKeypair, PublicKey as Libp2pSecpPublicKey,
            SecretKey as Libp2pSecpSecretKey,
        },
        PublicKey as Libp2pPublicKey,
    };
    use musig2::secp256k1::SECP256K1;
    use strata_bridge_test_utils::prelude::generate_keypair;
    use strata_common::logging::{self, LoggerConfig};
    use strata_p2p::events::Event;
    use strata_p2p_types::{
        OperatorPubKey, Scope, Wots160PublicKey, Wots256PublicKey, WotsPublicKeys,
    };
    use tokio::time::{sleep, Duration};
    use tracing::{error, info, trace};

    use crate::{
        bootstrap::bootstrap,
        config::Configuration,
        constants::{DEFAULT_IDLE_CONNECTION_TIMEOUT, DEFAULT_NUM_THREADS},
        message_handler::MessageHandler,
    };

    static SK_A: LazyLock<SecretKey> = {
        LazyLock::new(|| {
            let keypair = generate_keypair();
            keypair.secret_key()
        })
    };
    static X_ONLY_PK_A: LazyLock<XOnlyPublicKey> =
        LazyLock::new(|| SK_A.x_only_public_key(SECP256K1).0);
    static SK_B: LazyLock<SecretKey> = {
        LazyLock::new(|| {
            let keypair = generate_keypair();
            keypair.secret_key()
        })
    };
    static X_ONLY_PK_B: LazyLock<XOnlyPublicKey> =
        LazyLock::new(|| SK_B.x_only_public_key(SECP256K1).0);
    static SK_C: LazyLock<SecretKey> = {
        LazyLock::new(|| {
            let keypair = generate_keypair();
            keypair.secret_key()
        })
    };
    static X_ONLY_PK_C: LazyLock<XOnlyPublicKey> =
        LazyLock::new(|| SK_C.x_only_public_key(SECP256K1).0);

    /// Setups a node with the given port and peers.
    async fn setup_node(
        port: u16,
        peers: Vec<XOnlyPublicKey>,
        secret_key: SecretKey,
        connect_to: Vec<u16>,
    ) -> (MessageHandler, tokio_util::sync::CancellationToken) {
        // Parsing Stuff
        let secret_key = Libp2pSecpSecretKey::try_from_bytes(secret_key.secret_bytes()).unwrap();
        trace!(?secret_key, "parsed secret key into libp2p's secret key");

        let keypair: Libp2pSecpKeypair = secret_key.into();
        trace!(?keypair, "parsed libp2p's keypair");

        let idle_connection_timeout = Duration::from_secs(DEFAULT_IDLE_CONNECTION_TIMEOUT as u64);
        trace!(?idle_connection_timeout, "parsed idle_connection_timeout");

        let listening_addr: Multiaddr = format!("/ip4/127.0.0.1/tcp/{port}").parse().unwrap();

        let allowlist: Vec<PeerId> = peers
            .iter()
            .map(|x_only_pk| {
                let bytes = &x_only_pk.public_key(Parity::Even).serialize();
                let public_key = Libp2pSecpPublicKey::try_from_bytes(bytes)
                    .expect("Must read the 33-byte public key");
                let public_key: Libp2pPublicKey = public_key.into();
                let peer_id: PeerId = public_key.into();
                peer_id
            })
            .collect();
        trace!(?allowlist, "parsed allowlist");

        let connect_to: Vec<Multiaddr> = connect_to
            .iter()
            .map(|port| {
                let address = format!("/ip4/127.0.0.1/tcp/{port}");
                address.parse::<Multiaddr>().unwrap()
            })
            .collect();
        let connect_to: Vec<Multiaddr> = connect_to.into_iter().map(Into::into).collect();
        trace!(?connect_to, "parsed connect_to");

        let signers_allowlist: Vec<OperatorPubKey> = peers
            .iter()
            .map(|x_only_pk| {
                let bytes = &x_only_pk.public_key(Parity::Even).serialize();
                let public_key = Libp2pSecpPublicKey::try_from_bytes(bytes)
                    .expect("Must read the 33-byte public key");
                let operator_pk: OperatorPubKey = public_key.into();
                operator_pk
            })
            .collect();
        trace!(?signers_allowlist, "parsed signers_allowlist");

        let num_threads = Some(DEFAULT_NUM_THREADS);
        trace!(?num_threads, "parsed num_threads");

        // Create config for this node
        let config = Configuration {
            keypair: keypair.clone(),
            idle_connection_timeout,
            listening_addr,
            allowlist,
            connect_to,
            signers_allowlist,
            num_threads,
        };

        // Bootstrap the node
        let (handle, cancel) = bootstrap(&config).await.expect("Failed to bootstrap node");

        // Create a message handler
        let handler = MessageHandler::new(handle, keypair);

        (handler, cancel)
    }

    /// Tests message authentication and gossiping between nodes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn message_authentication_and_gossip() {
        logging::init(LoggerConfig::new("p2p-node".to_string()));

        let peers_a = vec![*X_ONLY_PK_B, *X_ONLY_PK_C];
        let peers_b = vec![*X_ONLY_PK_A, *X_ONLY_PK_C];
        let peers_c = vec![*X_ONLY_PK_A, *X_ONLY_PK_B];

        let port_a = 10_000;
        let port_b = 10_001;
        let port_c = 10_002;

        // Setup three nodes on different ports
        // Connect nodes in a chain: A -> B -> C
        // Node B connects to A
        // Node C connects to B
        let (handler_a, cancel_a) = setup_node(port_a, peers_a, *SK_A, vec![port_b]).await;
        let (mut handler_b, cancel_b) = setup_node(port_b, peers_b, *SK_B, vec![port_c]).await;
        let (mut handler_c, cancel_c) = setup_node(port_c, peers_c, *SK_C, vec![port_b]).await;

        // Wait for connections to establish
        // FIXME(@storopoli): Check if this delay is sufficient and trim it down if needed
        sleep(Duration::from_secs(2)).await;

        // Create channels to collect received messages
        let (tx_b, mut rx_b) = tokio::sync::mpsc::channel(50_000);
        let (tx_c, mut rx_c) = tokio::sync::mpsc::channel(50_000);

        // Spawn listeners for nodes B and C
        tokio::spawn(async move {
            loop {
                match handler_b.handle.next_event().await {
                    Ok(Event::ReceivedMessage(msg)) => {
                        info!("Node B received message: {:?}", msg);
                        let _ = tx_b.send(msg).await;
                    }
                    Err(e) => {
                        error!("Node B error: {:?}", e);
                        break;
                    }
                }
            }
        });

        tokio::spawn(async move {
            loop {
                match handler_c.handle.next_event().await {
                    Ok(Event::ReceivedMessage(msg)) => {
                        info!("Node C received message: {:?}", msg);
                        let _ = tx_c.send(msg).await;
                    }
                    Err(e) => {
                        error!("Node C error: {:?}", e);
                        break;
                    }
                }
            }
        });

        // Create a test deposit setup message from Node A
        let scope = Scope::hash([0u8; 32].as_slice());
        let public_inputs = vec![Wots256PublicKey::new([[0u8; 20]; 68])];
        let fqs = vec![Wots256PublicKey::new([[0u8; 20]; 68])];
        let hashes = vec![Wots160PublicKey::new([[0u8; 20]; 44])];
        let wots_pks = WotsPublicKeys::new(public_inputs, fqs, hashes);

        // Send the message from Node A
        handler_a.send_deposit_setup(scope, wots_pks.clone()).await;

        // Wait for the message to propagate
        sleep(Duration::from_secs(5)).await;

        // Check if Node B received the message with timeout
        // FIXME(@storopoli): Check if this delay is sufficient and trim it down if needed
        let received_by_b = tokio::time::timeout(Duration::from_secs(10), rx_b.recv())
            .await
            .is_ok();
        assert!(
            received_by_b,
            "Node B did not receive the message from Node A"
        );

        // Check if Node C received the message (gossip from B) with timeout
        // FIXME(@storopoli): Check if this delay is sufficient and trim it down if needed
        let received_by_c = tokio::time::timeout(Duration::from_secs(10), rx_c.recv())
            .await
            .is_ok();
        assert!(
            received_by_c,
            "Node C did not receive the message from Node B (gossip)"
        );

        // Clean up
        cancel_a.cancel();
        cancel_b.cancel();
        cancel_c.cancel();
    }
}
