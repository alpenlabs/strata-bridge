use std::{path::PathBuf, time::Duration};

use libp2p::{Multiaddr, PeerId};
use serde::{Deserialize, Serialize};
use strata_bridge_db::persistent::config::DbConfig;
use strata_p2p_types::P2POperatorPubKey;

/// The configuration values that dictate the behavior of the bridge node.
///
/// These values are not consensus-critical and can be changed by the operator i.e., differences in
/// what values are set by individual bridge node operators will not necessarily cause the bridge to
/// halt. It is still preferable to have these values be the same for optimum functioning of the
/// bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Config {
    /// The number of confirmations required for a transaction to be considered final.
    ///
    /// This is not consensus-critical as difference in what value is set by individual bridge node
    /// operators will only cause delays while exchanging information but will not halt the
    /// functioning of the bridge.
    pub finality_depth: u8,

    /// The directory to store all the data in.
    pub datadir: PathBuf,

    /// The RPC server addr for the bridge node.
    pub rpc_addr: String,

    /// The configuration required to connector to a _local_ instance of the secret service server.
    pub secret_service_client: SecretServiceConfig,

    /// The configuration required to connector to an instance of the bitcoin client.
    pub btc_client: BtcClientConfig,

    /// The configuration for the sqlite3 database.
    pub db: DbConfig,

    /// The configuration for the P2P.
    pub p2p: P2PConfig,

    /// Whether the bridge node is faulty.
    ///
    /// Here, faulty behavior means that the bridge node will post invalid proofs during assertion
    /// and can thus, be disproved and slashed.
    ///
    /// NOTE: This is only for testing purposes and *must* not be used in production.
    pub is_faulty: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SecretServiceConfig {
    /// The address of the secret service server.
    pub server_addr: String,

    /// The hostname present on the server's certificate.
    pub server_hostname: String,

    /// The timeout for requests.
    pub timeout: u64,

    /// The path to the server's TLS certificate chain.
    pub tls_certs: PathBuf,

    /// The path to the server's root ca certificate.
    pub tls_ca: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BtcClientConfig {
    pub url: String,
    pub user: String,
    pub pass: String,
    pub retry_count: Option<u8>,
    pub retry_interval: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct P2PConfig {
    /// Idle connection timeout.
    pub idle_connection_timeout: Option<Duration>,

    /// The node's address.
    pub listening_addr: Multiaddr,

    /// List of [`PeerId`]s that the node is allowed to connect to.
    pub allowlist: Vec<PeerId>,

    /// Initial list of nodes to connect to at startup.
    pub connect_to: Vec<Multiaddr>,

    /// List of signers' public keys, whose messages the node is allowed to accept.
    pub signers_allowlist: Vec<P2POperatorPubKey>,

    /// The number of threads to use for the in memory database.
    ///
    /// Default is
    /// [`DEFAULT_NUM_THREADS`](strata_bridge_p2p_service::constants::DEFAULT_NUM_THREADS).
    pub num_threads: Option<usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_serde_toml() {
        let config = r#"
            finality_depth = 6
            datadir = ".data"
            rpc_addr = "localhost:5678"
            is_faulty = false

            [secret_service_client]
            server_addr = "localhost:1234"
            server_hostname = "localhost"
            timeout = 1000
            tls_certs = "certs.pem"
            tls_ca = "ca.pem"

            [btc_client]
            url = "http://localhost:18443"
            user = "user"
            pass = "password"
            retry_count = 3
            retry_interval = 1000

            [db]
            max_retry_count = 3
            backoff_period = { secs = 1000, nanos = 0 }

            [p2p]
            idle_connection_timeout = { secs = 1000, nanos = 0 }
            listening_addr = "/ip4/127.0.0.1/tcp/1234"
            # taken from <https://github.com/libp2p/specs/blob/master/peer-ids/peer-ids.md#decoding>
            allowlist = ["12D3KooWD3eckifWpRn9wQpMG9R9hX3sD158z7EqHWmweQAJU5SA"]
            connect_to = ["/ip4/127.0.0.1/tcp/5678", "/ip4/127.0.0.1/tcp/9012"]
            signers_allowlist = ["c46132cbb3ef14caeac8f724fea1449d802133495ef1675f210b0742f5ee8164"]
            num_threads = 4
        "#;

        let config = toml::from_str::<Config>(config);
        assert!(
            config.is_ok(),
            "must be able to deserialize config from toml but got: {}",
            config.unwrap_err()
        );

        let config = config.unwrap();
        let serialized = toml::to_string(&config).unwrap();
        let deserialized = toml::from_str::<Config>(&serialized).unwrap();
        assert_eq!(
            deserialized, config,
            "must be able to serialize and deserialize config to toml"
        );
    }
}
