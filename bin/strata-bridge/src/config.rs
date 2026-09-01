//! Configuration values for the bridge node.
//!
//! These do not affect consensus between bridge nodes and can be set to different values by
//! different operators.
use std::{
    fmt,
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    path::PathBuf,
    time::Duration,
};

use bitcoin::BlockHash;

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
use strata_bridge_primitives::types::OperatorIdx;
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

    /// How long a nag reply suppresses repeat nags for the same data. Defaults to half of
    /// `nag_interval` so a peer's retry after a lost reply is still served; zero disables it.
    pub nag_dedup_window: Option<Duration>,

    /// How long an unsettled nag reply suppresses repeat nags, bounding the cost of a reply that
    /// hangs. Defaults to `nag_interval`, so a hung reply costs peers one nag round. Zero turns
    /// this off, so only a sent reply suppresses repeats.
    pub nag_dedup_in_flight_timeout: Option<Duration>,

    /// The interval at which to retry duties.
    pub retry_interval: Duration,

    /// The minimum number of blocks required between the current block height and the withdrawwal
    /// fulfillment deadline in order to perform a fulfillment.
    pub min_withdrawal_fulfillment_window: u64,

    /// Timeout for shutdown operations.
    pub shutdown_timeout: Duration,

    /// The number of blocks to wait before considering the cooperative payout path unviable and
    /// start with the unilateral reimbursement process. Once all the payout partials have been
    /// collected, the cooperative payout path is never abandoned.
    ///
    /// If set to `0`, the bridge will not wait and will immediately start with the unilateral
    /// reimbursement process. The node will also not accept any requests for cooperative payouts
    /// from its peers in this case.
    pub cooperative_payout_timeout: u16,

    /// The maximum fee rate for any transaction (in sats/vb).
    pub max_fee_rate: u64,

    /// Upper bound on the deposits this node takes part in at once: every deposit holding funds
    /// in the bridge plus every deposit request still being signed. Spent, aborted and skipped
    /// deposits do not count.
    ///
    /// Absent means unlimited; `0` admits no new deposit. A deposit request that arrives at the
    /// cap is still registered, so the deposit index advances identically on every operator
    /// whatever cap each one runs, but it is recorded as skipped: this node never acts on it and
    /// the depositor reclaims it after the recovery delay. Operators may run different values; a
    /// request skipped here and admitted elsewhere never completes, and it holds one of the
    /// admitting operators' slots until the depositor reclaims it.
    pub max_active_deposits: Option<u32>,
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

    /// Developer/experimentation mode. When `true`, the startup consistency checks are skipped.
    #[serde(default)]
    pub dev: bool,

    /// Skips the timelock ordering checks on the params; only for tests that need out-of-order
    /// timelocks.
    #[serde(default)]
    pub allow_unsafe_timelocks: bool,

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
///
/// `Debug` is implemented by hand so neither half of the RPC credential is printed. Operator
/// startup logs the whole [`Config`] at debug level, and those records reach stdout, rolling
/// files, and the OTLP collector, so a derived `Debug` would copy the credential to every enabled
/// sink.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
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

impl fmt::Debug for BtcClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BtcClientConfig")
            .field("url", &self.url)
            .field("user", &"<redacted>")
            .field("pass", &"<redacted>")
            .field("retry_count", &self.retry_count)
            .field("retry_interval", &self.retry_interval)
            .finish()
    }
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct P2PConfig {
    /// Idle connection timeout.
    pub idle_connection_timeout: Option<Duration>,

    /// Node's address.
    pub listening_addr: Multiaddr,

    /// Network addresses of other operators, keyed by their params registration.
    ///
    /// Entry order carries no meaning. Registrations without an entry are never dialed but may
    /// still connect to this node.
    pub peers: Vec<P2PPeerConfig>,

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

    /// Rate-limit score charged per accepted peer message; see
    /// [`OperatorValidator::message_cost`](strata_bridge_p2p_service::validator::OperatorValidator::message_cost).
    ///
    /// If [`None`], defaults to
    /// [`DEFAULT_MESSAGE_COST`](strata_bridge_p2p_service::validator::DEFAULT_MESSAGE_COST).
    pub rate_limit_message_cost: Option<f64>,

    /// Rate-limit score below which a peer is muted. Must be negative. See
    /// [`OperatorValidator::mute_threshold`](strata_bridge_p2p_service::validator::OperatorValidator::mute_threshold).
    ///
    /// If [`None`], defaults to
    /// [`DEFAULT_MUTE_THRESHOLD`](strata_bridge_p2p_service::validator::DEFAULT_MUTE_THRESHOLD).
    pub rate_limit_mute_threshold: Option<f64>,

    /// Rate-limit score a peer recovers per second; see
    /// [`OperatorValidator::recovery_per_sec`](strata_bridge_p2p_service::validator::OperatorValidator::recovery_per_sec).
    ///
    /// If [`None`], defaults to
    /// [`DEFAULT_RECOVERY_PER_SEC`](strata_bridge_p2p_service::validator::DEFAULT_RECOVERY_PER_SEC).
    pub rate_limit_recovery_per_sec: Option<f64>,

    /// How long a peer that crosses the mute threshold stays muted; see
    /// [`OperatorValidator::mute_duration`](strata_bridge_p2p_service::validator::OperatorValidator::mute_duration).
    ///
    /// If [`None`], defaults to
    /// [`DEFAULT_MUTE_DURATION`](strata_bridge_p2p_service::validator::DEFAULT_MUTE_DURATION).
    pub rate_limit_mute_duration: Option<Duration>,

    /// Size of the inbound gossip event buffer; see
    /// [`Configuration::gossip_event_buffer_size`](strata_bridge_p2p_service::Configuration::gossip_event_buffer_size).
    ///
    /// If [`None`], defaults to
    /// [`DEFAULT_GOSSIP_EVENT_BUFFER_SIZE`](strata_bridge_p2p_service::constants::DEFAULT_GOSSIP_EVENT_BUFFER_SIZE).
    pub gossip_event_buffer_size: Option<NonZeroUsize>,

    /// Size of the outbound gossip command queue; see
    /// [`Configuration::gossip_command_buffer_size`](strata_bridge_p2p_service::Configuration::gossip_command_buffer_size).
    ///
    /// If [`None`], defaults to
    /// [`DEFAULT_GOSSIP_COMMAND_BUFFER_SIZE`](strata_bridge_p2p_service::constants::DEFAULT_GOSSIP_COMMAND_BUFFER_SIZE).
    pub gossip_command_buffer_size: Option<NonZeroUsize>,
}

/// Network addresses at which one operator's P2P node listens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct P2PPeerConfig {
    /// The operator's permanent index in params.
    pub operator_idx: OperatorIdx,

    /// Addresses to dial, in order of preference.
    ///
    /// An address may end in `/p2p/<peer-id>`, which must name the identity of the operator's
    /// params P2P key.
    pub addrs: Vec<Multiaddr>,
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
///
/// `deny_unknown_fields` so a mistyped key — e.g. `[operator_wallet.firebloks]` — is a hard
/// error rather than silently deserializing `fireblocks` as `None` and downgrading a
/// Fireblocks-custodied operator to the native backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperatorWalletConfig {
    /// The size of the claim funding pool, i.e., the number of UTXOs to generate for funding claim
    /// transactions when they run out.
    pub claim_funding_pool_size: usize,

    /// Directory holding the persisted chain state of the general and reserved wallets, one SQLite
    /// file each. Created on first start if absent.
    pub data_dir: PathBuf,

    /// Number of applied blocks between commits of wallet state during a sync. Bounds the work a
    /// crash mid-sync can lose. Defaults to
    /// [`DEFAULT_PERSIST_EVERY_BLOCKS`](operator_wallet::DEFAULT_PERSIST_EVERY_BLOCKS).
    #[serde(default)]
    pub persist_every_blocks: Option<NonZeroU32>,

    /// Height of the first block that wallet stores created on this start scan. Unset or `0`
    /// means Bitcoin genesis. Set it at or below the oldest unspent output either wallet owns;
    /// anything below it is invisible. Stores that already exist resume from their own tip and
    /// are not rescanned from this value.
    #[serde(default)]
    pub bootstrap_height: Option<u64>,

    /// Hash the block at [`Self::bootstrap_height`] must have. Startup fails when the connected
    /// node reports a different hash, which is what catches a node following another chain. This
    /// is checked on every start, whether or not the stores already exist. A height on its own
    /// identifies no chain, so leaving this unset trusts whichever block the node happens to
    /// have there.
    #[serde(default)]
    pub bootstrap_block_hash: Option<BlockHash>,

    /// When present, the operator's general wallet is custodied in Fireblocks instead of a local
    /// BDK wallet. When absent (the default), the native backend is used. The reserved wallet is
    /// always native regardless.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fireblocks: Option<FireblocksWalletConfig>,
}

/// Connection + identity configuration for a Fireblocks-backed general wallet.
///
/// `Debug` is hand-written to redact `api_key`: the whole [`Config`] is logged at startup
/// (`mode/operator.rs`), so a derived `Debug` would leak the API key into the logs.
///
/// `deny_unknown_fields` so a mistyped credential key surfaces as a config error instead of
/// being silently dropped.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// BIP44 address index (`bip44AddressIndex`) telling Fireblocks which derived key under the
    /// vault to RAW-sign with. Must correspond to `deposit_address`. Defaults to `0` (the
    /// vault's default address).
    #[serde(default)]
    pub bip44_address_index: u32,

    /// BIP44 change index (`bip44change`). `0` for receive, `1` for internal. Defaults to `0`.
    #[serde(default)]
    pub bip44_change: u32,
}

impl fmt::Debug for FireblocksWalletConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact the API key; everything else is non-secret operational config.
        f.debug_struct("FireblocksWalletConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .field("vault_account_id", &self.vault_account_id)
            .field("asset_id", &self.asset_id)
            .field("deposit_address", &self.deposit_address)
            .field("api_secret_path", &self.api_secret_path)
            .field("bip44_address_index", &self.bip44_address_index)
            .field("bip44_change", &self.bip44_change)
            .finish()
    }
}

/// Configuration for the mosaic client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MosaicConfig {
    /// Mosaic RPC HTTP endpoint (local mosaic instance).
    pub rpc_url: String,

    /// Delay between retries for network/protocol errors.
    pub retry_delay: Duration,

    /// Maximum number of retries per RPC call.
    pub max_retries: usize,

    /// Poll interval for watched deposits.
    pub poll_interval: Duration,

    /// Mosaic peer ID of every operator registered in params, including this node.
    ///
    /// Entry order carries no meaning.
    pub peers: Vec<MosaicPeerConfig>,
}

/// Mosaic peer ID of one operator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct MosaicPeerConfig {
    /// The operator's permanent index in params.
    pub operator_idx: OperatorIdx,

    /// The operator's 32-byte hex-encoded Mosaic peer ID.
    pub peer_id: String,
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

/// Shared config fixture for tests.
///
/// The Bitcoin RPC credentials are sentinels so `debug_redacts_btc_rpc_credentials` can search
/// rendered output for them without matching field names or other values.
#[cfg(test)]
/// Everything except the `[operator_wallet]` table, so individual tests can append
/// different operator-wallet configurations (native vs Fireblocks).
pub(crate) const BASE_TOML: &str = r#"
            num_threads = 4
            thread_stack_size = 8_388_608 # 8 * 1024 * 1024
            is_faulty = false
            nag_interval = { secs = 60, nanos = 0 }
            retry_interval = { secs = 21600, nanos = 0 } # 6 hours
            min_withdrawal_fulfillment_window = 143
            shutdown_timeout = { secs = 15, nanos = 0 }
            cooperative_payout_timeout = 144 # ~24 hours
            max_fee_rate = 10 # sats/vbyte
            max_active_deposits = 2

            [secret_service_client]
            server_addr = "localhost:1234"
            server_hostname = "localhost"
            timeout = 1_000
            cert = "cert.pem"
            key = "key.pem"
            service_ca = "ca.pem"

            [btc_client]
            url = "http://localhost:18443"
            user = "sentinel-user"
            pass = "sentinel-password"
            retry_count = 3
            retry_interval = 1_000

            [db]
            cluster_file_path = "/etc/foundationdb/fdb.cluster"
            retry = { retry_limit = 5, timeout = { secs = 5, nanos = 0 } }

            [p2p]
            idle_connection_timeout = { secs = 1_000, nanos = 0 }
            listening_addr = "/ip4/127.0.0.1/tcp/1234"
            peers = [
                { operator_idx = 2, addrs = ["/ip4/127.0.0.1/tcp/9012"] },
                { operator_idx = 1, addrs = ["/ip4/127.0.0.1/tcp/5678", "/dns4/bridge-1/tcp/5678"] },
            ]
            num_threads = 4
            dial_timeout = { secs = 0, nanos = 250_000_000 }
            general_timeout = { secs = 0, nanos = 250_000_000 }
            connection_check_interval = { secs = 0, nanos = 500_000_000 }
            gossipsub_scoring_preset = "permissive"
            rate_limit_mute_threshold = -50_000
            rate_limit_mute_duration = { secs = 5, nanos = 0 }
            gossip_event_buffer_size = 8192

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

            [mosaic]
            rpc_url = "http://localhost:7500"
            retry_delay = { secs = 2, nanos = 0 }
            max_retries = 5
            poll_interval = { secs = 5, nanos = 0 }
            peers = [
                { operator_idx = 1, peer_id = "0000000000000000000000000000000000000000000000000000000000000002" },
                { operator_idx = 0, peer_id = "0000000000000000000000000000000000000000000000000000000000000001" },
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

/// A full parsed test config with the native operator-wallet backend. Startup-check tests
/// and config tests share this constructor.
#[cfg(test)]
pub(crate) fn test_config() -> Config {
    toml::from_str(&format!(
        "{BASE_TOML}\n\
         [operator_wallet]\n\
         claim_funding_pool_size = 32\n\
         data_dir = \"wallet-data\"\n\
         bootstrap_height = 101\n\
         bootstrap_block_hash = \"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f\"\n"
    ))
    .expect("valid test config")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Parses `toml_str` and asserts a serde round-trip preserves every field, returning the
    /// parsed config.
    fn assert_roundtrips(toml_str: &str) -> Config {
        let config = toml::from_str::<Config>(toml_str)
            .unwrap_or_else(|e| panic!("must deserialize config from toml: {e}"));
        let serialized = toml::to_string(&config).unwrap();
        let reparsed = toml::from_str::<Config>(&serialized).unwrap();
        let reserialized = toml::to_string(&reparsed).unwrap();
        assert_eq!(
            reserialized, serialized,
            "serde round-trip must preserve every field"
        );
        config
    }

    #[test]
    fn test_config_serde_toml() {
        let toml_str = format!(
            "{BASE_TOML}\n\
             [operator_wallet]\n\
             claim_funding_pool_size = 32\n\
             data_dir = \"wallet-data\"\n\
             bootstrap_height = 101\n\
             bootstrap_block_hash = \"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f\"\n"
        );
        let config = assert_roundtrips(&toml_str);
        assert!(
            config.operator_wallet.fireblocks.is_none(),
            "no fireblocks table => native backend"
        );
    }

    #[test]
    fn test_config_serde_toml_with_fireblocks() {
        let toml_str = format!(
            "{BASE_TOML}\n\
             [operator_wallet]\n\
             claim_funding_pool_size = 32\n\
             data_dir = \"wallet-data\"\n\
             bootstrap_height = 101\n\
             bootstrap_block_hash = \"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f\"\n\n\
             [operator_wallet.fireblocks]\n\
             base_url = \"https://api.fireblocks.io\"\n\
             api_key = \"api-key-id\"\n\
             vault_account_id = \"0\"\n\
             asset_id = \"BTC\"\n\
             deposit_address = \"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq\"\n\
             api_secret_path = \"fireblocks_secret.pem\"\n"
        );
        let config = assert_roundtrips(&toml_str);
        let fb = config
            .operator_wallet
            .fireblocks
            .expect("fireblocks table => Fireblocks backend");
        assert_eq!(fb.asset_id, "BTC");
        assert_eq!(fb.vault_account_id, "0");
        assert_eq!(fb.api_secret_path, PathBuf::from("fireblocks_secret.pem"));
    }

    #[test]
    fn max_active_deposits_absent_means_unlimited() {
        assert_eq!(test_config().max_active_deposits, Some(2));

        let without_cap: String = toml::to_string(&test_config())
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("max_active_deposits"))
            .map(|line| format!("{line}\n"))
            .collect();
        let config = toml::from_str::<Config>(&without_cap).unwrap();

        assert_eq!(config.max_active_deposits, None);
    }

    // Operator startup logs the whole config, so no debug rendering of it may carry the Bitcoin
    // RPC credentials, neither the leaf struct nor the parent that holds it.
    #[test]
    fn p2p_rate_limit_fields_are_optional_and_accept_integers() {
        let p2p = test_config().p2p;
        assert_eq!(p2p.rate_limit_mute_threshold, Some(-50_000.0));
        assert_eq!(p2p.rate_limit_mute_duration, Some(Duration::from_secs(5)));
        assert_eq!(p2p.rate_limit_message_cost, None);
        assert_eq!(p2p.rate_limit_recovery_per_sec, None);
    }

    #[test]
    fn p2p_peers_are_keyed_by_operator_index() {
        let peers = test_config().p2p.peers;

        assert_eq!(
            peers,
            vec![
                P2PPeerConfig {
                    operator_idx: 2,
                    addrs: vec!["/ip4/127.0.0.1/tcp/9012".parse().expect("valid multiaddr")],
                },
                P2PPeerConfig {
                    operator_idx: 1,
                    addrs: vec![
                        "/ip4/127.0.0.1/tcp/5678".parse().expect("valid multiaddr"),
                        "/dns4/bridge-1/tcp/5678".parse().expect("valid multiaddr"),
                    ],
                },
            ],
            "each peer entry must keep its operator index and every address"
        );
    }

    #[test]
    fn mosaic_peers_are_keyed_by_operator_index() {
        let peers = test_config().mosaic.peers;

        assert_eq!(
            peers
                .iter()
                .map(|peer| (peer.operator_idx, peer.peer_id.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (
                    1,
                    "0000000000000000000000000000000000000000000000000000000000000002"
                ),
                (
                    0,
                    "0000000000000000000000000000000000000000000000000000000000000001"
                ),
            ],
            "each mosaic peer entry must keep its operator index and peer ID"
        );
    }

    #[test]
    fn mosaic_config_rejects_unknown_fields() {
        let unkeyed = r#"
            rpc_url = "http://localhost:7500"
            retry_delay = { secs = 2, nanos = 0 }
            max_retries = 5
            poll_interval = { secs = 5, nanos = 0 }
            peers = []
            peer_ids = ["0000000000000000000000000000000000000000000000000000000000000001"]
        "#;

        assert!(
            toml::from_str::<MosaicConfig>(unkeyed).is_err(),
            "peer IDs outside a keyed peer entry must not be silently ignored"
        );
    }

    #[test]
    fn p2p_config_rejects_unknown_fields() {
        let unkeyed = r#"
            listening_addr = "/ip4/127.0.0.1/tcp/1234"
            peers = []
            connect_to = ["/ip4/127.0.0.1/tcp/5678"]
        "#;

        assert!(
            toml::from_str::<P2PConfig>(unkeyed).is_err(),
            "addresses outside a keyed peer entry must not be silently ignored"
        );
    }

    #[test]
    fn p2p_gossip_buffer_sizes_are_optional_and_nonzero() {
        let p2p = test_config().p2p;
        assert_eq!(p2p.gossip_event_buffer_size, NonZeroUsize::new(8192));
        assert_eq!(p2p.gossip_command_buffer_size, None);

        let zero = r#"
            listening_addr = "/ip4/127.0.0.1/tcp/1234"
            peers = []
            gossip_command_buffer_size = 0
        "#;
        assert!(toml::from_str::<P2PConfig>(zero).is_err());
    }

    #[test]
    fn debug_redacts_btc_rpc_credentials() {
        let config = test_config();

        for rendered in [
            format!("{:?}", config.btc_client),
            format!("{:#?}", config.btc_client),
            format!("{config:?}"),
        ] {
            assert!(
                !rendered.contains("sentinel-password"),
                "password leaked: {rendered}"
            );
            assert!(
                !rendered.contains("sentinel-user"),
                "username leaked: {rendered}"
            );
        }

        // Non-secret fields stay visible so the startup record remains a usable diagnostic.
        let rendered = format!("{:?}", config.btc_client);
        assert!(rendered.contains("http://localhost:18443"));
        assert!(rendered.contains("retry_count: Some(3)"));
    }
}
