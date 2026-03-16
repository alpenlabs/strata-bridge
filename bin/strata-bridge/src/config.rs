//! Configuration values for the bridge node.
//!
//! These do not affect consensus between bridge nodes and can be set to different values by
//! different operators.
use std::{path::PathBuf, time::Duration};

use btc_tracker::config::BtcNotifyConfig;
use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};
use strata_bridge_asm_events::config::AsmRpcConfig;
use strata_bridge_db::fdb::cfg::Config as FdbConfig;
use strata_bridge_p2p_service::GossipsubScoringPreset;

/// Configuration values that dictate the behavior of the bridge node.
///
/// These values are not consensus-critical and can be changed by the operator i.e., differences in
/// what values are set by individual bridge node operators will not necessarily cause the bridge to
/// halt. It is still preferable to have some of these values be the same for optimum functioning of
/// the bridge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Config {
    /// Number of threads to use for the runtime.
    pub num_threads: Option<u8>,

    /// Per-thread stack size to use (in bytes) for the runtime.
    pub thread_stack_size: Option<usize>,

    /// The interval at which to nag peers for required MuSig2 information.
    pub nag_interval: Duration,

    /// The interval at which to retry duties.
    pub retry_interval: Duration,

    /// The minimum number of blocks required between the current block height and the withdrawwal
    /// fulfillment deadline in order to perform a fulfillment.
    pub min_withdrawal_fulfillment_window: u64,

    /// Timeout for shutdown operations.
    pub shutdown_timeout: Duration,

    /// The number of blocks to wait before considering the cooperative payout path unviable and
    /// start with the unilateral reimbursement process.
    ///
    /// If set to `0`, the bridge will not wait and will immediately start with the unilateral
    /// reimbursement process. The node will also not accept any requests for cooperative payouts
    /// from its peers in this case.
    pub cooperative_payout_timeout: u16,

    /// The maximum fee rate for any transaction (in sats/vb).
    pub max_fee_rate: u64,

    /// Configuration required to connector to a _local_ instance of the secret service server.
    pub secret_service_client: SecretServiceConfig,

    /// Configuration required to connector to an instance of the bitcoin client.
    pub btc_client: BtcClientConfig,

    /// Configuration for the database.
    pub db: FdbConfig,

    /// Configuration for the P2P.
    pub p2p: P2PConfig,

    /// Configuration for the RPC server.
    pub rpc: RpcConfig,

    /// Configuration for the ASM RPC assignments feed.
    pub asm_rpc: AsmRpcConfig,

    /// Configuration for the Bitcoin ZMQ client.
    pub btc_zmq: BtcNotifyConfig,

    /// Configuration for the operator wallet.
    pub operator_wallet: OperatorWalletConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SecretServiceConfig {
    /// Address of the secret service server.
    pub server_addr: String,

    /// Hostname present on the server's certificate.
    pub server_hostname: String,

    /// Timeout for requests.
    pub timeout: u64,

    /// Path to the bridge's TLS cert used for client authentication.
    pub cert: PathBuf,
    /// Path to the bridge's TLS key used for client authentication.
    pub key: PathBuf,

    /// Path to the secret service's certificate authority cert chain used to verify their
    /// authenticity.
    pub service_ca: PathBuf,
}

/// Configuration for the Bitcoin client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct BtcClientConfig {
    /// URL of the Bitcoin client.
    pub url: String,

    /// Username for the Bitcoin client.
    pub user: String,

    /// Password for the Bitcoin client.
    pub pass: String,

    /// Optional retry count for failed requests.
    pub retry_count: Option<u8>,

    /// Optional retry interval for failed requests.
    pub retry_interval: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct P2PConfig {
    /// Idle connection timeout.
    pub idle_connection_timeout: Option<Duration>,

    /// Node's address.
    pub listening_addr: Multiaddr,

    /// Initial list of nodes to connect to at startup.
    pub connect_to: Vec<Multiaddr>,

    /// Number of threads to use for the in memory database.
    ///
    /// Default is
    /// [`DEFAULT_NUM_THREADS`](strata_bridge_p2p_service::constants::DEFAULT_NUM_THREADS).
    pub num_threads: Option<usize>,

    /// Dial timeout.
    ///
    /// Default is [`DEFAULT_DIAL_TIMEOUT`](strata_p2p::swarm::DEFAULT_DIAL_TIMEOUT).
    pub dial_timeout: Option<Duration>,

    /// General timeout for operations.
    ///
    /// Default is [`DEFAULT_GENERAL_TIMEOUT`](strata_p2p::swarm::DEFAULT_GENERAL_TIMEOUT).
    pub general_timeout: Option<Duration>,

    /// Connection check interval.
    ///
    /// Default is
    /// [`DEFAULT_CONNECTION_CHECK_INTERVAL`](strata_p2p::swarm::DEFAULT_CONNECTION_CHECK_INTERVAL).
    pub connection_check_interval: Option<Duration>,

    /// Target number of peers in the gossipsub mesh.
    ///
    /// Default is 6 (libp2p gossipsub default).
    pub gossipsub_mesh_n: Option<usize>,

    /// Minimum number of peers in the gossipsub mesh before grafting more.
    ///
    /// Default is 5 (libp2p gossipsub default).
    pub gossipsub_mesh_n_low: Option<usize>,

    /// Maximum number of peers in the gossipsub mesh before pruning.
    ///
    /// Default is 12 (libp2p gossipsub default).
    pub gossipsub_mesh_n_high: Option<usize>,

    /// Gossipsub peer scoring preset.
    ///
    /// If not specified, defaults to `default` which uses libp2p's standard
    /// scoring parameters.
    ///
    /// Set to `permissive` for test networks.
    pub gossipsub_scoring_preset: Option<GossipsubScoringPreset>,

    /// Initial delay for the gossipsub heartbeat.
    pub gossipsub_heartbeat_initial_delay: Option<Duration>,

    /// The duration a message to be published can wait to be sent before it is abandoned.
    ///
    /// If [`None`], defaults to libp2p's default of 5 seconds.
    pub gossipsub_publish_queue_duration: Option<Duration>,

    /// The duration a message to be forwarded can wait to be sent before it is abandoned.
    ///
    /// If [`None`], defaults to libp2p's default of 1 second.
    pub gossipsub_forward_queue_duration: Option<Duration>,
}

/// RPC server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct RpcConfig {
    /// RPC server address.
    pub rpc_addr: String,

    /// Optional refresh interval for the RPC server state cache.
    ///
    /// Default is
    /// [`DEFAULT_RPC_CACHE_REFRESH_INTERVAL`](crate::constants::DEFAULT_RPC_CACHE_REFRESH_INTERVAL).
    pub refresh_interval: Option<Duration>,
}

/// Configuration for the operator wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OperatorWalletConfig {
    /// The size of the claim funding pool, i.e., the number of UTXOs to generate for funding claim
    /// transactions when they run out.
    pub claim_funding_pool_size: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_serde_toml() {
        let config = r#"
            num_threads = 4
            thread_stack_size = 8_388_608 # 8 * 1024 * 1024
            is_faulty = false
            nag_interval = { secs = 60, nanos = 0 }
            retry_interval = { secs = 21600, nanos = 0 } # 6 hours
            min_withdrawal_fulfillment_window = 144
            shutdown_timeout = { secs = 15, nanos = 0 }
            cooperative_payout_timeout = 144 # ~24 hours
            max_fee_rate = 10 # sats/vbyte

            [secret_service_client]
            server_addr = "localhost:1234"
            server_hostname = "localhost"
            timeout = 1_000
            cert = "cert.pem"
            key = "key.pem"
            service_ca = "ca.pem"

            [btc_client]
            url = "http://localhost:18443"
            user = "user"
            pass = "password"
            retry_count = 3
            retry_interval = 1_000

            [db]
            cluster_file_path = "/etc/foundationdb/fdb.cluster"
            retry = { retry_limit = 5, timeout = { secs = 5, nanos = 0 } }

            [p2p]
            idle_connection_timeout = { secs = 1_000, nanos = 0 }
            listening_addr = "/ip4/127.0.0.1/tcp/1234"
            connect_to = ["/ip4/127.0.0.1/tcp/5678", "/ip4/127.0.0.1/tcp/9012"]
            num_threads = 4
            dial_timeout = { secs = 0, nanos = 250_000_000 }
            general_timeout = { secs = 0, nanos = 250_000_000 }
            connection_check_interval = { secs = 0, nanos = 500_000_000 }
            gossipsub_scoring_preset = "permissive"

            [rpc]
            rpc_addr = "localhost:5678"
            refresh_interval = {secs = 600, nanos = 0 }

            [asm_rpc]
            rpc_url = "http://localhost:9010"
            request_timeout = { secs = 2, nanos = 0 }
            max_retries = 10
            retry_initial_delay = { secs = 1, nanos = 0 }
            retry_max_delay = { secs = 60, nanos = 0 }
            retry_multiplier = 2

            [btc_zmq]
            bury_depth = 6
            hashblock_connection_string = "tcp://127.0.0.1:28332"
            hashtx_connection_string = "tcp://127.0.0.1:28333"
            rawblock_connection_string = "tcp://127.0.0.1:28334"
            rawtx_connection_string = "tcp://127.0.0.1:28335"
            sequence_connection_string = "tcp://127.0.0.1:28336"

            [operator_wallet]
            claim_funding_pool_size = 32
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
