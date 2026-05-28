//! Configuration values for the bridge node.
//!
//! These do not affect consensus between bridge nodes and can be set to different values by
//! different operators.
use std::{net::SocketAddr, path::PathBuf, time::Duration};

/// Default cadence for the background fee-rate refresh task — see
/// [`Config::fee_refresh_interval`].
const fn default_fee_refresh_interval() -> Duration {
    Duration::from_secs(30)
}

/// Default cadence for the CPFP bump-check timer — see [`Config::cpfp_bump_check_interval`].
const fn default_cpfp_bump_check_interval() -> Duration {
    Duration::from_secs(30)
}

use libp2p::Multiaddr;
use serde::{Deserialize, Serialize};
use strata_bridge_asm_events::config::AsmRpcConfig;
pub(crate) use strata_bridge_counterproof::ProofBackendConfig as CounterproofBackendConfig;
use strata_bridge_db::fdb::cfg::Config as FdbConfig;
use strata_bridge_p2p_service::GossipsubScoringPreset;
pub(crate) use strata_bridge_proof::ProofBackendConfig;

/// Configuration values that dictate the behavior of the bridge node.
///
/// These values are not consensus-critical and can be changed by the operator i.e., differences in
/// what values are set by individual bridge node operators will not necessarily cause the bridge to
/// halt. It is still preferable to have some of these values be the same for optimum functioning of
/// the bridge.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Background-refresh cadence for the cached fee rate. The bridge spawns a tokio task at
    /// startup that polls the configured fee source at this interval and stores the result in
    /// a shared atomic; the CPFP bump loop reads from that cache instead of hitting the
    /// underlying source per call. Defaults to 30 seconds.
    #[serde(default = "default_fee_refresh_interval")]
    pub fee_refresh_interval: Duration,

    /// Cadence at which the CPFP bump loop polls the cached fee rate and attempts an RBF bump
    /// of any active CPFP parent whose current package rate is below the new target. Defaults
    /// to 30 seconds. Set higher to reduce wallet-lock contention; set lower for snappier
    /// reaction to fee-market moves between blocks.
    #[serde(default = "default_cpfp_bump_check_interval")]
    pub cpfp_bump_check_interval: Duration,

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
    pub btc_zmq: BtcZmqConfig,

    /// Configuration for the operator wallet.
    pub operator_wallet: OperatorWalletConfig,

    /// Configuration for the mosaic client.
    pub mosaic: MosaicConfig,

    /// Backend that produces bridge proofs.
    pub bridge_proof: ProofBackendConfig,

    /// Backend that produces bridge counterproofs.
    pub counterproof: CounterproofBackendConfig,

    /// Configuration for process-level metrics exporters.
    #[serde(default)]
    pub metrics: MetricsConfig,
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

/// Configuration for the Bitcoin ZMQ client.
///
/// The burial threshold is intentionally excluded from this node-local config because it is
/// consensus-critical for the bridge. It lives in [`strata_bridge_common::params::ProtocolParams`]
/// instead.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BtcZmqConfig {
    /// Connection string used in `bitcoin.conf => zmqpubhashblock`.
    pub hashblock_connection_string: Option<String>,

    /// Connection string used in `bitcoin.conf => zmqpubhashtx`.
    pub hashtx_connection_string: Option<String>,

    /// Connection string used in `bitcoin.conf => zmqpubrawblock`.
    pub rawblock_connection_string: Option<String>,

    /// Connection string used in `bitcoin.conf => zmqpubrawtx`.
    pub rawtx_connection_string: Option<String>,

    /// Connection string used in `bitcoin.conf => zmqpubsequence`.
    pub sequence_connection_string: Option<String>,
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

    /// Interval between re-dial attempts for peers that have become disconnected.
    ///
    /// If [`None`], defaults to
    /// [`DEFAULT_PEER_RECONNECT_INTERVAL`](strata_bridge_p2p_service::constants::DEFAULT_PEER_RECONNECT_INTERVAL).
    pub peer_reconnect_interval: Option<Duration>,
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

    /// When present, the operator's general wallet is custodied in Fireblocks instead of a local
    /// BDK wallet. When absent (the default), the native backend is used. The reserved wallet is
    /// always native regardless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fireblocks: Option<FireblocksWalletConfig>,
}

/// Connection + identity configuration for a Fireblocks-backed general wallet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FireblocksWalletConfig {
    /// API host root, **without** the `/v1` path segment, e.g. `https://api.fireblocks.io`.
    pub base_url: String,

    /// Fireblocks API key (sent as the `X-API-Key` header).
    pub api_key: String,

    /// Vault account id holding the BTC asset.
    pub vault_account_id: String,

    /// Asset id for the network — `BTC` on mainnet, `BTC_TEST` on test networks.
    pub asset_id: String,

    /// The vault account's BTC deposit address (P2WPKH). Where the general wallet receives
    /// funding and earnings.
    pub deposit_address: String,

    /// Path to the Fireblocks API secret — an RSA private key in PEM form, used to sign the
    /// per-request JWTs. Kept out of the config body (like the secret-service TLS material) so
    /// the key never lives in the config file itself.
    pub api_secret_path: PathBuf,
}

/// Configuration for the mosaic client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MosaicConfig {
    /// Mosaic RPC HTTP endpoint (local mosaic instance).
    pub rpc_url: String,

    /// Delay between retries for network/protocol errors.
    pub retry_delay: Duration,

    /// Maximum number of retries per RPC call.
    pub max_retries: usize,

    /// Poll interval for watched deposits.
    pub poll_interval: Duration,

    /// Mosaic peer IDs for each operator, ordered by operator index.
    /// Each entry is a 32-byte hex-encoded peer ID.
    pub peer_ids: Vec<String>,
}

/// Configuration for bridge process metrics exporters.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct MetricsConfig {
    /// Optional OTLP endpoint URL for metrics export.
    ///
    /// If unset, the bridge reuses `STRATA_BRIDGE_OTLP_URL` when present.
    pub otlp_url: Option<String>,

    /// Optional Prometheus listener address, for example `0.0.0.0:9615`.
    pub prometheus_listener_addr: Option<SocketAddr>,
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
            hashblock_connection_string = "tcp://127.0.0.1:28332"
            hashtx_connection_string = "tcp://127.0.0.1:28333"
            rawblock_connection_string = "tcp://127.0.0.1:28334"
            rawtx_connection_string = "tcp://127.0.0.1:28335"
            sequence_connection_string = "tcp://127.0.0.1:28336"

            [operator_wallet]
            claim_funding_pool_size = 32

            [mosaic]
            rpc_url = "http://localhost:7500"
            retry_delay = { secs = 2, nanos = 0 }
            max_retries = 5
            poll_interval = { secs = 5, nanos = 0 }
            peer_ids = [
                "0000000000000000000000000000000000000000000000000000000000000001",
                "0000000000000000000000000000000000000000000000000000000000000002",
            ]

            [bridge_proof]
            kind = "native"
            schnorr_signing_key = "0101010101010101010101010101010101010101010101010101010101010101"

            [counterproof]
            kind = "native"
            schnorr_signing_key = "0202020202020202020202020202020202020202020202020202020202020202"

            [metrics]
            prometheus_listener_addr = "127.0.0.1:9615"
        "#;

        let config = toml::from_str::<Config>(config);
        assert!(
            config.is_ok(),
            "must be able to deserialize config from toml but got: {}",
            config.unwrap_err()
        );

        let config = config.unwrap();
        let serialized = toml::to_string(&config).unwrap();
        let reparsed = toml::from_str::<Config>(&serialized).unwrap();
        let reserialized = toml::to_string(&reparsed).unwrap();
        assert_eq!(
            reserialized, serialized,
            "serde round-trip must preserve every field"
        );
    }
}
