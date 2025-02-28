//! Strata Bridge P2P.

pub mod bootstrap;
pub mod config;
pub mod constants;
pub mod message_handler;

pub use bootstrap::bootstrap;
pub use config::Configuration;
pub use message_handler::MessageHandler;

#[cfg(test)]
mod tests {
    use std::sync::{Arc, LazyLock};

    use bitcoin::{key::Parity, secp256k1::SecretKey, XOnlyPublicKey};
    use libp2p::{build_multiaddr, Multiaddr, PeerId};
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
    use strata_p2p::{
        events::Event,
        swarm::{self, handle::P2PHandle, P2PConfig, P2P},
    };
    use strata_p2p_db::sled::AsyncDB;
    use strata_p2p_types::{OperatorPubKey, Scope, WotsPublicKeys};
    use threadpool::ThreadPool;
    use tokio::{
        sync::mpsc,
        time::{sleep, timeout, Duration},
    };
    use tokio_util::sync::CancellationToken;
    use tracing::{error, info, trace};

    use crate::{
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
    ) -> (P2P<AsyncDB>, MessageHandler, CancellationToken) {
        // Parsing Stuff
        let secret_key = Libp2pSecpSecretKey::try_from_bytes(secret_key.secret_bytes()).unwrap();
        trace!(?secret_key, "parsed secret key into libp2p's secret key");

        let keypair: Libp2pSecpKeypair = secret_key.into();
        trace!(?keypair, "parsed libp2p's keypair");

        let idle_connection_timeout = Duration::from_secs(DEFAULT_IDLE_CONNECTION_TIMEOUT as u64);
        trace!(?idle_connection_timeout, "parsed idle_connection_timeout");

        let listening_addr: Multiaddr = build_multiaddr!(Ip4([127, 0, 0, 1]), Tcp(port));

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
            .map(|port| build_multiaddr!(Ip4([127, 0, 0, 1]), Tcp(*port)))
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
        let (p2p, handle, cancel) = test_bootstrap(&config).expect("Failed to bootstrap node");

        // Create a message handler
        let handler = MessageHandler::new(handle, keypair);

        (p2p, handler, cancel)
    }

    /// Modified [`bootstrap`](crate::bootstrap) function to allow testing without a real network
    /// connection.
    fn test_bootstrap(
        config: &Configuration,
    ) -> anyhow::Result<(P2P<AsyncDB>, P2PHandle, CancellationToken)> {
        let p2p_config = P2PConfig {
            keypair: config.keypair.clone(),
            idle_connection_timeout: config.idle_connection_timeout,
            listening_addr: config.listening_addr.clone(),
            allowlist: config.allowlist.clone(),
            connect_to: config.connect_to.clone(),
            signers_allowlist: config.signers_allowlist.clone(),
        };
        let cancellation_token = CancellationToken::new();

        info!("creating an in-memory sled database");
        let db = sled::Config::new().temporary(true).open()?;
        let pool = ThreadPool::new(config.num_threads.unwrap_or(DEFAULT_NUM_THREADS));
        let db = AsyncDB::new(pool, Arc::new(db));

        info!("creating a swarm");
        let swarm = swarm::with_tcp_transport(&p2p_config)?;

        info!("creating a p2p node");
        let (p2p, handle) =
            P2P::from_config(p2p_config, cancellation_token.clone(), db, swarm, None)?;

        Ok((p2p, handle, cancellation_token))
    }

    /// Tests message authentication and gossiping between nodes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 6)]
    async fn message_authentication_and_gossip() {
        logging::init(LoggerConfig::new("p2p-node".to_string()));

        let peers = vec![*X_ONLY_PK_A, *X_ONLY_PK_B, *X_ONLY_PK_C];

        let port_a = 10_000;
        let port_b = 10_001;
        let port_c = 10_002;

        // Setup three nodes on different ports
        // A -- B -- C
        let (mut p2p_a, handler_a, cancel_a) =
            setup_node(port_a, peers.clone(), *SK_A, vec![port_b]).await;
        let (mut p2p_b, mut handler_b, cancel_b) =
            setup_node(port_b, peers.clone(), *SK_B, vec![port_a, port_c]).await;
        let (mut p2p_c, mut handler_c, cancel_c) =
            setup_node(port_c, peers.clone(), *SK_C, vec![port_b]).await;

        // Spawn tasks to run the p2p nodes
        let listen_a = tokio::spawn(async move {
            // Establish connections for node A
            sleep(Duration::from_secs(2)).await;
            info!("Node A establishing connections");
            let _ = p2p_a.establish_connections().await;

            // Listen for events on node A
            sleep(Duration::from_secs(2)).await;
            info!("Node A listening for events");
            let _ = p2p_a.listen().await;
        });
        let listen_b = tokio::spawn(async move {
            // Establish connections for node B
            sleep(Duration::from_secs(2)).await;
            info!("Node B establishing connections");
            let _ = p2p_b.establish_connections().await;

            // Listen for events on node B
            sleep(Duration::from_secs(2)).await;
            info!("Node B listening for events");
            let _ = p2p_b.listen().await;
        });
        let listen_c = tokio::spawn(async move {
            // Establish connections for node C
            sleep(Duration::from_secs(2)).await;
            info!("Node C establishing connections");
            let _ = p2p_c.establish_connections().await;

            // Listen for events on node C
            sleep(Duration::from_secs(2)).await;
            info!("Node C listening for events");
            let _ = p2p_c.listen().await;
        });

        // Wait for connections to establish
        sleep(Duration::from_secs(3)).await;

        // Create channels to collect received messages
        let (tx_b, mut rx_b) = mpsc::channel(50_000);
        let (tx_c, mut rx_c) = mpsc::channel(50_000);

        // Spawn listeners for nodes B through E
        tokio::spawn(async move {
            loop {
                match handler_b.handle.next_event().await {
                    Ok(Event::ReceivedMessage(msg)) => {
                        info!(?msg, "Node B received message from Node A");
                        let _ = tx_b.send(msg).await;
                    }
                    Err(e) => {
                        error!(?e, "Node B error:");
                        break;
                    }
                }
            }
        });
        tokio::spawn(async move {
            loop {
                match handler_c.handle.next_event().await {
                    Ok(Event::ReceivedMessage(msg)) => {
                        info!(?msg, "Node C received message from Node B");
                        let _ = tx_c.send(msg).await;
                    }
                    Err(e) => {
                        error!(?e, "Node C error:");
                        break;
                    }
                }
            }
        });

        // Wait for gossip to subscribe
        sleep(Duration::from_secs(5)).await;

        // Create a test deposit setup message from Node A
        let scope = Scope::hash(b"scope");
        let mock_bytes = [0u8; 362_960];
        let wots_pks = WotsPublicKeys::from_flattened_bytes(&mock_bytes);

        // Send the message from Node A
        handler_a.send_deposit_setup(scope, wots_pks.clone()).await;

        // Wait for the message to propagate
        sleep(Duration::from_secs(10)).await;

        // Check if Node B received the message with timeout
        let received_by_b = timeout(Duration::from_secs(15), rx_b.recv()).await.is_ok();
        assert!(received_by_b, "Node B did not receive the deposit setup");

        // Check if Node C received the message with timeout
        let received_by_c = timeout(Duration::from_secs(15), rx_c.recv()).await.is_ok();
        assert!(received_by_c, "Node C did not receive the deposit setup");

        // Clean up
        cancel_a.cancel();
        cancel_b.cancel();
        cancel_c.cancel();

        let _ = tokio::join!(listen_a, listen_b, listen_c);
    }
}
