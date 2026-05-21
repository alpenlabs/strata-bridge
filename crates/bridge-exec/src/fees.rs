//! Fee-rate sources for bridge transactions.
//!
//! Provides a [`FeeSource`] trait with three implementations:
//!
//! * [`BitcoindFeeSource`] — queries `estimatesmartfee` on the local Bitcoin Core RPC.
//! * [`MempoolExplorerFeeSource`] — queries a mempool.space-compatible explorer's
//!   `/api/v1/fees/recommended` endpoint; falls back to a wrapped [`BitcoindFeeSource`] on any HTTP
//!   or decode failure so a downed mempool explorer never blocks tx publishing.
//! * [`FixedFeeSource`] — returns a constant rate (tests, manual overrides).
//!
//! All sources clamp the returned rate to at least 1 sat/vB. `bitcoind-async-client` represents
//! fee rates as `u64` sat/vB, so any sub-1 sat/vB estimate from the upstream source would
//! otherwise truncate to zero and lose the fee entirely. This mirrors strata's fix in
//! [alpenlabs/alpen#1811](https://github.com/alpenlabs/alpen/pull/1811).
//!
//! Callers fetch via [`FeeSource::estimate`] once per tx-build. Periodic re-fetching for live
//! fee tracking (e.g., to drive RBF bumps) is the responsibility of the caller, not the source;
//! that loop will live in the tx-driver layer once CPFP wiring lands
//! ([STR-3439](https://alpenlabs.atlassian.net/browse/STR-3439)).

use std::{
    sync::{Arc, LazyLock},
    time::Duration,
};

use async_trait::async_trait;
use bitcoin::FeeRate;
use bitcoind_async_client::{ClientResult, traits::Reader};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;
use url::Url;

/// Narrow trait covering only the RPC surface the fee source needs.
///
/// Auto-implemented for every [`Reader`], and tests can implement it directly without modeling
/// the dozens of other [`Reader`] methods. The fallback path only needs `estimate_smart_fee`,
/// so the trait stays single-method on purpose.
#[async_trait]
pub trait FeeRateRpc: Send + Sync + std::fmt::Debug {
    /// See [`Reader::estimate_smart_fee`].
    async fn estimate_smart_fee(&self, conf_target: u16) -> ClientResult<u64>;
}

#[async_trait]
impl<R: Reader + std::fmt::Debug + Send + Sync> FeeRateRpc for R {
    async fn estimate_smart_fee(&self, conf_target: u16) -> ClientResult<u64> {
        <R as Reader>::estimate_smart_fee(self, conf_target).await
    }
}

/// Errors produced by [`FeeSource`] implementations.
#[derive(Debug, Error)]
pub enum FeeSourceError {
    /// Bitcoin Core RPC reported an error.
    #[error("bitcoind: {0}")]
    Bitcoind(#[from] bitcoind_async_client::error::ClientError),
    /// The mempool explorer call failed (HTTP error, non-2xx, or timeout).
    ///
    /// Surfaced only when there is no fallback; configured fallbacks absorb this internally.
    #[error("mempool explorer: {0}")]
    MempoolHttp(String),
    /// The mempool explorer response could not be decoded as the expected JSON shape.
    ///
    /// Surfaced only when there is no fallback; configured fallbacks absorb this internally.
    #[error("mempool explorer decode: {0}")]
    MempoolDecode(String),
    /// The configured mempool explorer URL is malformed.
    #[error("invalid mempool explorer url: {0}")]
    InvalidConfig(String),
}

/// A source of fee-rate estimates for bridge transactions.
///
/// Implementations are stateless with respect to fee tracking — each call hits the underlying
/// source. Callers responsible for cadence; see module docs.
///
/// Uses `async_trait` rather than AFIT so the trait is object-safe and can be stored as
/// `Arc<dyn FeeSource>` on [`crate::config::ExecutionConfig`]. Allocation cost per call is one
/// boxed future, negligible against the network round-trip the call performs.
#[async_trait]
pub trait FeeSource: Send + Sync + std::fmt::Debug {
    /// Returns the current fee-rate estimate, clamped to at least 1 sat/vB.
    async fn estimate(&self) -> Result<FeeRate, FeeSourceError>;
}

// ────────────────────────────────────────────────────────────────────────────
// Bitcoin Core
// ────────────────────────────────────────────────────────────────────────────

/// Fee source backed by Bitcoin Core's `estimatesmartfee`.
///
/// Note: Bitcoin Core's `estimatesmartfee` ignores the current mempool entirely — it only looks
/// at recent block fees. Useful as a fallback or for closed networks, but on a public network
/// with a varied mempool the [`MempoolExplorerFeeSource`] gives more responsive estimates.
#[derive(Debug, Clone)]
pub struct BitcoindFeeSource<R> {
    client: Arc<R>,
    conf_target: u16,
}

impl<R: FeeRateRpc> BitcoindFeeSource<R> {
    /// Creates a new source that queries `estimatesmartfee(conf_target)` on `client`.
    pub const fn new(client: Arc<R>, conf_target: u16) -> Self {
        Self {
            client,
            conf_target,
        }
    }
}

#[async_trait]
impl<R: FeeRateRpc> FeeSource for BitcoindFeeSource<R> {
    async fn estimate(&self) -> Result<FeeRate, FeeSourceError> {
        let raw = self
            .client
            .estimate_smart_fee(self.conf_target)
            .await
            .map_err(FeeSourceError::Bitcoind)?;
        Ok(clamp_to_min(raw))
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Mempool explorer (mempool.space-compatible)
// ────────────────────────────────────────────────────────────────────────────

/// Recommended-fee tier to consume from the mempool explorer response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MempoolFeePolicy {
    /// `fastestFee` — designed to confirm in the next block.
    Fastest,
    /// `halfHourFee`.
    HalfHour,
    /// `hourFee`.
    Hour,
    /// `economyFee` — willing to wait several blocks for cheaper.
    Economy,
    /// `minimumFee`.
    Minimum,
}

/// Response from a mempool.space-compatible `/api/v1/fees/recommended` endpoint.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
struct RecommendedFees {
    #[serde(rename = "fastestFee")]
    fastest_fee: u64,
    #[serde(rename = "halfHourFee")]
    half_hour_fee: u64,
    #[serde(rename = "hourFee")]
    hour_fee: u64,
    #[serde(rename = "economyFee")]
    economy_fee: u64,
    #[serde(rename = "minimumFee")]
    minimum_fee: u64,
}

impl RecommendedFees {
    const fn select(self, policy: MempoolFeePolicy) -> u64 {
        match policy {
            MempoolFeePolicy::Fastest => self.fastest_fee,
            MempoolFeePolicy::HalfHour => self.half_hour_fee,
            MempoolFeePolicy::Hour => self.hour_fee,
            MempoolFeePolicy::Economy => self.economy_fee,
            MempoolFeePolicy::Minimum => self.minimum_fee,
        }
    }
}

/// Shared HTTP client used for all mempool explorer lookups. Pooled for connection reuse —
/// every call would otherwise pay the TLS handshake.
///
/// The 10-second total timeout is the load-bearing knob here: `reqwest::Client::new()` defaults
/// to no timeout, which means a hanging mempool explorer would indefinitely block the duty
/// future awaiting `estimate()`. The fallback to Bitcoin Core only triggers on an error result,
/// not on a never-resolving future. 10s is a conservative cap — recommended-fees responses are
/// small, hosted on a CDN, and arrive in well under a second under normal conditions.
static SHARED_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("reqwest::Client::builder with rustls-tls; failure here means a build-time misconfiguration")
});

/// Fee source backed by a mempool.space-compatible explorer's recommended-fees endpoint, with
/// a Bitcoin Core fallback.
///
/// Falls back to the wrapped [`BitcoindFeeSource`] on any HTTP error, non-2xx status, or decode
/// failure. The fallback error replaces the mempool error in the result; the mempool error is
/// only logged. This matches strata's behaviour: a downed mempool explorer must never block tx
/// publishing.
#[derive(Debug, Clone)]
pub struct MempoolExplorerFeeSource<R> {
    recommended_fees_url: Url,
    policy: MempoolFeePolicy,
    fallback: BitcoindFeeSource<R>,
}

impl<R: FeeRateRpc> MempoolExplorerFeeSource<R> {
    /// Creates a new source that GETs `{base_url}/api/v1/fees/recommended` and selects the field
    /// indicated by `policy`. `base_url` is e.g. `https://mempool.space/signet` or
    /// `https://mempool.space` for mainnet.
    ///
    /// Returns an error if `base_url` is malformed enough that we cannot construct the
    /// recommended-fees URL from it.
    pub fn new(
        base_url: Url,
        policy: MempoolFeePolicy,
        fallback: BitcoindFeeSource<R>,
    ) -> Result<Self, FeeSourceError> {
        // Ensure the base URL has a trailing slash so `Url::join` treats it as a directory.
        // Without this, `join("api/v1/fees/recommended")` would replace the last path segment.
        let mut url = base_url;
        if !url.path().ends_with('/') {
            let path = format!("{}/", url.path());
            url.set_path(&path);
        }
        let recommended_fees_url = url
            .join("api/v1/fees/recommended")
            .map_err(|e| FeeSourceError::InvalidConfig(format!("{e:?}")))?;
        Ok(Self {
            recommended_fees_url,
            policy,
            fallback,
        })
    }

    async fn fetch_recommended(&self) -> Result<RecommendedFees, FeeSourceError> {
        let response = SHARED_HTTP_CLIENT
            .get(self.recommended_fees_url.clone())
            .send()
            .await
            .map_err(|e| FeeSourceError::MempoolHttp(format!("{e}")))?
            .error_for_status()
            .map_err(|e| FeeSourceError::MempoolHttp(format!("{e}")))?;
        response
            .json::<RecommendedFees>()
            .await
            .map_err(|e| FeeSourceError::MempoolDecode(format!("{e}")))
    }
}

#[async_trait]
impl<R: FeeRateRpc> FeeSource for MempoolExplorerFeeSource<R> {
    async fn estimate(&self) -> Result<FeeRate, FeeSourceError> {
        match self.fetch_recommended().await {
            Ok(fees) => Ok(clamp_to_min(fees.select(self.policy))),
            Err(e) => {
                warn!(error = %e, "mempool explorer fee lookup failed; falling back to bitcoind");
                self.fallback.estimate().await
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Fixed (for tests / manual overrides)
// ────────────────────────────────────────────────────────────────────────────

/// Fee source that returns a constant rate, regardless of network conditions.
///
/// Intended for tests and emergency manual overrides. Returns the configured rate verbatim —
/// no clamping. If you set this to a value below 1 sat/vB you'll get what you ask for.
#[derive(Debug, Clone, Copy)]
pub struct FixedFeeSource(pub FeeRate);

impl FixedFeeSource {
    /// Creates a new fixed source from a sat/vB integer rate.
    pub fn from_sat_per_vb(rate: u64) -> Option<Self> {
        FeeRate::from_sat_per_vb(rate).map(Self)
    }
}

#[async_trait]
impl FeeSource for FixedFeeSource {
    async fn estimate(&self) -> Result<FeeRate, FeeSourceError> {
        Ok(self.0)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Config + builder
// ────────────────────────────────────────────────────────────────────────────

/// Serializable operator-side configuration that selects a [`FeeSource`] policy.
///
/// Built into a concrete `Arc<dyn FeeSource>` at startup via [`FeeSourceConfig::build`], taking
/// the operator's Bitcoin Core RPC client as the fallback source for the mempool variant.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FeeSourceConfig {
    /// Query Bitcoin Core's `estimatesmartfee(conf_target)` directly.
    BitcoinCore {
        /// Block confirmation target passed to `estimatesmartfee`. `1` mirrors the bridge's
        /// historical behaviour.
        conf_target: u16,
    },
    /// Query a mempool.space-compatible explorer's `/api/v1/fees/recommended` endpoint, with
    /// Bitcoin Core as the fallback if the explorer is unreachable.
    MempoolExplorer {
        /// Base URL, e.g. `https://mempool.space/signet` or `https://mempool.space`.
        base_url: Url,
        /// Which tier of the recommended-fees response to use.
        policy: MempoolFeePolicy,
        /// `conf_target` passed to `estimatesmartfee` on the fallback path.
        fallback_conf_target: u16,
    },
    /// Return a constant rate. Intended for tests and emergency manual overrides.
    Fixed {
        /// sat/vB.
        fee_rate: u64,
    },
}

impl FeeSourceConfig {
    /// Constructs the configured [`FeeSource`] from this config + a Bitcoin Core RPC client.
    ///
    /// `bitcoind` is used as the primary source for [`FeeSourceConfig::BitcoinCore`], and as the
    /// fallback for [`FeeSourceConfig::MempoolExplorer`].
    pub fn build<R>(self, bitcoind: Arc<R>) -> Result<Arc<dyn FeeSource>, FeeSourceError>
    where
        R: FeeRateRpc + 'static,
    {
        match self {
            Self::BitcoinCore { conf_target } => {
                Ok(Arc::new(BitcoindFeeSource::new(bitcoind, conf_target)))
            }
            Self::MempoolExplorer {
                base_url,
                policy,
                fallback_conf_target,
            } => {
                let fallback = BitcoindFeeSource::new(bitcoind, fallback_conf_target);
                Ok(Arc::new(MempoolExplorerFeeSource::new(
                    base_url, policy, fallback,
                )?))
            }
            Self::Fixed { fee_rate } => {
                let source = FixedFeeSource::from_sat_per_vb(fee_rate).ok_or_else(|| {
                    FeeSourceError::InvalidConfig(format!(
                        "fixed fee rate {fee_rate} sat/vB exceeds FeeRate's u64 sat/kwu range"
                    ))
                })?;
                Ok(Arc::new(source))
            }
        }
    }
}

impl Default for FeeSourceConfig {
    /// Defaults to Bitcoin Core with `conf_target = 1`, matching the bridge's historical
    /// behaviour before this abstraction landed.
    fn default() -> Self {
        Self::BitcoinCore { conf_target: 1 }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────────────

/// Clamps a raw sat/vB rate to a minimum of 1 sat/vB.
///
/// `bitcoind-async-client` represents fee rates as `u64` sat/vB; on networks (notably the
/// public signet) where the upstream source returns a sub-1 sat/vB rate, the value truncates
/// to 0 and we'd lose the fee entirely. Mirror strata's clamp (alpenlabs/alpen#1811) until
/// sub-1 sat/vB representation lands upstream.
///
/// On the upper end, `FeeRate::from_sat_per_vb` overflows its internal sat/kwu representation
/// at sat/vB > u64::MAX/250 ≈ 7.4×10^16, far beyond anything `estimatesmartfee` could ever
/// return. Falls back to 1 sat/vB on that overflow rather than panicking — defensive against
/// stubbed callers, not a real production path.
fn clamp_to_min(raw_sat_per_vb: u64) -> FeeRate {
    let clamped = raw_sat_per_vb.max(1);
    FeeRate::from_sat_per_vb(clamped)
        .unwrap_or_else(|| FeeRate::from_sat_per_vb(1).expect("1 sat/vB is always a valid FeeRate"))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use async_trait::async_trait;
    use bitcoind_async_client::{ClientResult, error::ClientError};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    /// Test stub for [`FeeRateRpc`]. Returns a configured rate or error; nothing else.
    #[derive(Debug)]
    struct MockFeeRateRpc {
        rate: ClientResult<u64>,
    }

    impl MockFeeRateRpc {
        fn returning(rate: u64) -> Self {
            Self { rate: Ok(rate) }
        }

        fn failing() -> Self {
            Self {
                rate: Err(ClientError::Request("boom".to_string())),
            }
        }
    }

    #[async_trait]
    impl FeeRateRpc for MockFeeRateRpc {
        async fn estimate_smart_fee(&self, _conf_target: u16) -> ClientResult<u64> {
            self.rate.clone()
        }
    }

    fn recommended_fees_body(
        fastest: u64,
        half_hour: u64,
        hour: u64,
        economy: u64,
        minimum: u64,
    ) -> serde_json::Value {
        serde_json::json!({
            "fastestFee": fastest,
            "halfHourFee": half_hour,
            "hourFee": hour,
            "economyFee": economy,
            "minimumFee": minimum,
        })
    }

    #[tokio::test]
    async fn bitcoind_happy_path() {
        let source = BitcoindFeeSource::new(Arc::new(MockFeeRateRpc::returning(5)), 1);
        let rate = source.estimate().await.unwrap();
        assert_eq!(rate, FeeRate::from_sat_per_vb(5).unwrap());
    }

    #[tokio::test]
    async fn bitcoind_floors_zero_to_one() {
        let source = BitcoindFeeSource::new(Arc::new(MockFeeRateRpc::returning(0)), 1);
        let rate = source.estimate().await.unwrap();
        assert_eq!(rate, FeeRate::from_sat_per_vb(1).unwrap());
    }

    #[tokio::test]
    async fn bitcoind_propagates_rpc_error() {
        let source = BitcoindFeeSource::new(Arc::new(MockFeeRateRpc::failing()), 1);
        let err = source.estimate().await.unwrap_err();
        assert!(matches!(err, FeeSourceError::Bitcoind(_)));
    }

    #[tokio::test]
    async fn mempool_happy_path_fastest() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(recommended_fees_body(10, 7, 5, 3, 1)),
            )
            .mount(&server)
            .await;

        let fallback = BitcoindFeeSource::new(Arc::new(MockFeeRateRpc::failing()), 1);
        let source = MempoolExplorerFeeSource::new(
            Url::parse(&server.uri()).unwrap(),
            MempoolFeePolicy::Fastest,
            fallback,
        )
        .unwrap();
        let rate = source.estimate().await.unwrap();
        assert_eq!(rate, FeeRate::from_sat_per_vb(10).unwrap());
    }

    #[tokio::test]
    async fn mempool_happy_path_economy() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(recommended_fees_body(10, 7, 5, 3, 1)),
            )
            .mount(&server)
            .await;

        let fallback = BitcoindFeeSource::new(Arc::new(MockFeeRateRpc::failing()), 1);
        let source = MempoolExplorerFeeSource::new(
            Url::parse(&server.uri()).unwrap(),
            MempoolFeePolicy::Economy,
            fallback,
        )
        .unwrap();
        let rate = source.estimate().await.unwrap();
        assert_eq!(rate, FeeRate::from_sat_per_vb(3).unwrap());
    }

    #[tokio::test]
    async fn mempool_fallback_on_5xx() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let fallback = BitcoindFeeSource::new(Arc::new(MockFeeRateRpc::returning(4)), 1);
        let source = MempoolExplorerFeeSource::new(
            Url::parse(&server.uri()).unwrap(),
            MempoolFeePolicy::Fastest,
            fallback,
        )
        .unwrap();
        let rate = source.estimate().await.unwrap();
        // Fallback succeeded; the mempool error is absorbed.
        assert_eq!(rate, FeeRate::from_sat_per_vb(4).unwrap());
    }

    #[tokio::test]
    async fn mempool_fallback_on_malformed_json() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(ResponseTemplate::new(200).set_body_string("not json"))
            .mount(&server)
            .await;

        let fallback = BitcoindFeeSource::new(Arc::new(MockFeeRateRpc::returning(6)), 1);
        let source = MempoolExplorerFeeSource::new(
            Url::parse(&server.uri()).unwrap(),
            MempoolFeePolicy::Fastest,
            fallback,
        )
        .unwrap();
        let rate = source.estimate().await.unwrap();
        assert_eq!(rate, FeeRate::from_sat_per_vb(6).unwrap());
    }

    #[tokio::test]
    async fn mempool_and_fallback_both_fail() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(ResponseTemplate::new(503))
            .mount(&server)
            .await;

        let fallback = BitcoindFeeSource::new(Arc::new(MockFeeRateRpc::failing()), 1);
        let source = MempoolExplorerFeeSource::new(
            Url::parse(&server.uri()).unwrap(),
            MempoolFeePolicy::Fastest,
            fallback,
        )
        .unwrap();
        // Mempool error is absorbed; surfaced error is from the bitcoind fallback.
        let err = source.estimate().await.unwrap_err();
        assert!(matches!(err, FeeSourceError::Bitcoind(_)));
    }

    #[tokio::test]
    async fn fixed_source_returns_configured_rate() {
        let source = FixedFeeSource::from_sat_per_vb(7).unwrap();
        let rate = source.estimate().await.unwrap();
        assert_eq!(rate, FeeRate::from_sat_per_vb(7).unwrap());
    }

    #[tokio::test]
    async fn mempool_base_url_without_trailing_slash_works() {
        // mempool.space/signet style — must still resolve to .../signet/api/v1/fees/recommended.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/signet/api/v1/fees/recommended"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(recommended_fees_body(12, 8, 6, 4, 2)),
            )
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/signet", server.uri())).unwrap();
        let fallback = BitcoindFeeSource::new(Arc::new(MockFeeRateRpc::failing()), 1);
        let source =
            MempoolExplorerFeeSource::new(base, MempoolFeePolicy::Fastest, fallback).unwrap();
        let rate = source.estimate().await.unwrap();
        assert_eq!(rate, FeeRate::from_sat_per_vb(12).unwrap());
    }

    #[test]
    fn clamp_to_min_handles_overflow_without_panicking() {
        // Far above any plausible `estimatesmartfee` output, but reachable from a stubbed
        // `Fixed { fee_rate: u64::MAX }` config or a misbehaving mock. Must return a finite
        // FeeRate, not panic.
        let rate = clamp_to_min(u64::MAX);
        assert_eq!(rate, FeeRate::from_sat_per_vb(1).unwrap());
    }

    #[test]
    fn fee_source_config_roundtrips_through_toml_bitcoincore() {
        let toml_str = r#"
            kind = "bitcoin_core"
            conf_target = 6
        "#;
        let cfg: FeeSourceConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(cfg, FeeSourceConfig::BitcoinCore { conf_target: 6 });
    }

    #[test]
    fn fee_source_config_roundtrips_through_toml_mempool() {
        let toml_str = r#"
            kind = "mempool_explorer"
            base_url = "https://mempool.space/signet"
            policy = "fastest"
            fallback_conf_target = 1
        "#;
        let cfg: FeeSourceConfig = toml::from_str(toml_str).unwrap();
        assert!(matches!(
            cfg,
            FeeSourceConfig::MempoolExplorer {
                policy: MempoolFeePolicy::Fastest,
                fallback_conf_target: 1,
                ..
            }
        ));
    }

    #[test]
    fn fee_source_config_roundtrips_through_toml_mempool_half_hour() {
        // Verifies the snake_case rename on MempoolFeePolicy works for multi-word variants.
        let toml_str = r#"
            kind = "mempool_explorer"
            base_url = "https://mempool.space"
            policy = "half_hour"
            fallback_conf_target = 1
        "#;
        let cfg: FeeSourceConfig = toml::from_str(toml_str).unwrap();
        assert!(matches!(
            cfg,
            FeeSourceConfig::MempoolExplorer {
                policy: MempoolFeePolicy::HalfHour,
                ..
            }
        ));
    }

    #[test]
    fn fee_source_config_default_is_bitcoin_core_conf_target_1() {
        // Preserves pre-PR behaviour for operators upgrading without touching their config.
        let cfg = FeeSourceConfig::default();
        assert_eq!(cfg, FeeSourceConfig::BitcoinCore { conf_target: 1 });
    }
}
