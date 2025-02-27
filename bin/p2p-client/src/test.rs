#[cfg(test)]
mod tests {
    use std::sync::LazyLock;

    use bitcoin::{
        key::{rand::thread_rng, Keypair, Parity},
        secp256k1::SecretKey,
        XOnlyPublicKey,
    };
    use libp2p_identity::secp256k1::{
        Keypair as Libp2pSecpKeypair, SecretKey as Libp2pSecpSecretKey,
    };
    use musig2::secp256k1::SECP256K1;
    use strata_common::logging::{self, LoggerConfig};
    use strata_p2p::events::Event;
    use strata_p2p_types::{Scope, Wots160PublicKey, Wots256PublicKey, WotsPublicKeys};
    use tokio::time::{sleep, Duration};
    use tracing::{error, info, trace};

    use crate::{
        bootstrap::bootstrap,
        cli::Cli,
        constants::{DEFAULT_IDLE_CONNECTION_TIMEOUT, DEFAULT_STACK_SIZE_MB},
        message_handler::MessageHandler,
    };

    static SK_A: LazyLock<SecretKey> = {
        LazyLock::new(|| {
            loop {
                let mut rng = thread_rng();
                let keypair = Keypair::new(SECP256K1, &mut rng);
                let (_, parity) = keypair.x_only_public_key();

                // Check if the public key is even (first byte is 0x02)
                if parity == Parity::Even {
                    return keypair.secret_key();
                }
            }
        })
    };
    static X_ONLY_PK_A: LazyLock<XOnlyPublicKey> =
        LazyLock::new(|| SK_A.x_only_public_key(SECP256K1).0);
    static SK_B: LazyLock<SecretKey> = {
        LazyLock::new(|| {
            loop {
                let mut rng = thread_rng();
                let keypair = Keypair::new(SECP256K1, &mut rng);
                let (_, parity) = keypair.x_only_public_key();

                // Check if the public key is even (first byte is 0x02)
                if parity == Parity::Even {
                    return keypair.secret_key();
                }
            }
        })
    };
    static X_ONLY_PK_B: LazyLock<XOnlyPublicKey> =
        LazyLock::new(|| SK_B.x_only_public_key(SECP256K1).0);
    static SK_C: LazyLock<SecretKey> = {
        LazyLock::new(|| {
            loop {
                let mut rng = thread_rng();
                let keypair = Keypair::new(SECP256K1, &mut rng);
                let (_, parity) = keypair.x_only_public_key();

                // Check if the public key is even (first byte is 0x02)
                if parity == Parity::Even {
                    return keypair.secret_key();
                }
            }
        })
    };
    static X_ONLY_PK_C: LazyLock<XOnlyPublicKey> =
        LazyLock::new(|| SK_C.x_only_public_key(SECP256K1).0);

    /// Setups a node with the given port and peers.
    async fn setup_node(
        port: u32,
        peers: Vec<XOnlyPublicKey>,
        secret_key: SecretKey,
        connect_to: Vec<u32>,
    ) -> (MessageHandler, tokio_util::sync::CancellationToken) {
        // Create CLI args for this node
        let args = Cli {
            host: "127.0.0.1".to_string(),
            port,
            num_threads: 1,
            stack_size: DEFAULT_STACK_SIZE_MB,
            idle_connection_timeout: DEFAULT_IDLE_CONNECTION_TIMEOUT,
            secret_key: secret_key.display_secret().to_string(),
            allowlist: peers.iter().map(|pk| pk.to_string()).collect(),
            connect_to: connect_to
                .iter()
                .map(|port| format!("127.0.0.1:{port}"))
                .collect(),
        };

        // Bootstrap the node
        let (handle, cancel) = bootstrap(args).await.expect("Failed to bootstrap node");

        // Create a message handler
        let secret_key = Libp2pSecpSecretKey::try_from_bytes(secret_key.secret_bytes()).unwrap();
        trace!(?secret_key, "parsed secret key into libp2p's secret key");

        let keypair: Libp2pSecpKeypair = secret_key.into();
        trace!(?keypair, "parsed libp2p's keypair");
        let handler = MessageHandler::new(handle, keypair);

        (handler, cancel)
    }

    /// Tests message authentication and gossiping between nodes.
    #[tokio::test(flavor = "multi_thread", worker_threads = 3)]
    async fn test_message_authentication_and_gossip() {
        logging::init(LoggerConfig::new("p2p-node".to_string()));

        let peers_a = vec![*X_ONLY_PK_B, *X_ONLY_PK_C];
        let peers_b = vec![*X_ONLY_PK_A, *X_ONLY_PK_C];
        let peers_c = vec![*X_ONLY_PK_A, *X_ONLY_PK_B];

        let port_a = 10_000;
        let port_b = 10_001;
        let port_c = 10_002;

        // Setup three nodes on different ports
        let (handler_a, cancel_a) = setup_node(port_a, peers_a, *SK_A, vec![port_b]).await;
        let (mut handler_b, cancel_b) = setup_node(port_b, peers_b, *SK_B, vec![port_c]).await;
        let (mut handler_c, cancel_c) = setup_node(port_c, peers_c, *SK_C, vec![port_b]).await;

        // Connect nodes in a chain: A -> B -> C
        // Node B connects to A
        // Node C connects to B

        // Wait for connections to establish
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

        // Check if Node B received the message
        let received_by_b = rx_b.try_recv().is_ok();
        assert!(
            received_by_b,
            "Node B did not receive the message from Node A"
        );

        // Check if Node C received the message (gossip from B)
        let received_by_c = rx_c.try_recv().is_ok();
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
