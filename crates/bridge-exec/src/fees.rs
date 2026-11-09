//! Fee-rate sources for bridge transactions.
//!
//! Provides three implementations of [`FeeSource`]:
//!
//! * `BitcoindFeeSource` — queries `estimatesmartfee` on the local Bitcoin Core RPC.
//! * `MempoolExplorerFeeSource` — queries a mempool.space-compatible explorer's
//!   `/api/v1/fees/recommended` endpoint; falls back to a wrapped `BitcoindFeeSource` on any HTTP
//!   or decode failure, or on a rate that overflows [`FeeRate`], so a downed mempool explorer never
//!   blocks tx publishing.
//! * `FixedFeeSource` — returns a constant rate (tests, manual overrides).
//!
//! The network-backed sources clamp their reported rate to `MIN_SOURCE_FEE_RATE`.
//!
//! The orchestrator builds the configured source via [`FeeSourceConfig::build`].

use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use bitcoin::FeeRate;
use bitcoind_async_client::{ClientResult, traits::Reader};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;
use url::Url;

/// Narrow trait covering only the RPC surface the fee source needs.
///
/// Auto-implemented for every [`Reader`]. Tests implement this one method and do not model the
/// dozens of other [`Reader`] methods.
#[async_trait]
pub trait FeeRateRpc: Send + Sync + std::fmt::Debug {
    /// See [`Reader::estimate_smart_fee`]. `None` means bitcoind had insufficient data to
    /// produce an estimate (fresh regtest, early signet).
    async fn estimate_smart_fee(&self, conf_target: u16) -> ClientResult<Option<FeeRate>>;
}

#[async_trait]
impl<R: Reader + std::fmt::Debug + Send + Sync> FeeRateRpc for R {
    async fn estimate_smart_fee(&self, conf_target: u16) -> ClientResult<Option<FeeRate>> {
        Ok(<R as Reader>::estimate_smart_fee(self, conf_target)
            .await?
            .fee_rate)
    }
}

/// A failed quote.
///
/// Every network-backed source ends on Bitcoin Core, because the explorer source absorbs its own
/// failures into the Core fallback.
#[derive(Debug, Clone, Error)]
pub enum FeeSourceError {
    /// The RPC failed. This is transient.
    #[error("bitcoind: {0}")]
    Bitcoind(#[from] bitcoind_async_client::error::ClientError),
    /// Core has no next-block estimate. That is normal on a fresh regtest. On a real network it
    /// means that the node is cold. A `-blocksonly` node does not report this: Core has no
    /// estimator there, so the RPC fails.
    #[error("bitcoind has no next-block fee estimate")]
    NoEstimate,
}

/// A [`FeeSourceConfig`] that cannot build a source. These are permanent.
#[derive(Debug, Error)]
pub enum FeeConfigError {
    /// The configured mempool explorer URL is malformed.
    #[error("invalid mempool explorer url: {0}")]
    InvalidExplorerUrl(String),
    /// The configured fixed rate overflows [`FeeRate`].
    #[error("fixed fee rate {0} sat/vB exceeds FeeRate's u64 sat/kwu range")]
    InvalidFixedRate(u64),
    /// The HTTP client for the mempool explorer cannot start.
    #[error("mempool explorer http client: {0}")]
    HttpClient(reqwest::Error),
}

/// A failed mempool explorer read. The source logs it (`warn`) and asks its Core fallback.
#[derive(Debug, Error)]
enum ExplorerError {
    /// The HTTP call failed (transport error, non-2xx, or timeout).
    #[error("http: {0}")]
    Http(reqwest::Error),
    /// The response is not the expected JSON shape.
    #[error("decode: {0}")]
    Decode(reqwest::Error),
    /// A tier in the response overflows [`FeeRate`].
    #[error("rate {0} sat/vB overflows FeeRate")]
    RateOverflow(u64),
}

/// Source of fee-rate estimates.
#[async_trait]
pub trait FeeSource: Send + Sync + fmt::Debug {
    /// Returns the next-block fee rate: `fastestFee` on the mempool explorer, confirmation target
    /// 1 on Bitcoin Core.
    ///
    /// On Bitcoin Core this is a lagging two-block economical estimate, not a next-block one. Core
    /// rewrites target 1 to 2, and `estimatesmartfee` runs in economical mode unless told
    /// otherwise. The estimate reads confirmed blocks, so it lags a backlog that grows.
    async fn next_block_rate(&self) -> Result<FeeRate, FeeSourceError>;
}

// ────────────────────────────────────────────────────────────────────────────
// Bitcoin Core
// ────────────────────────────────────────────────────────────────────────────

/// Fee source backed by Bitcoin Core's `estimatesmartfee`.
///
/// Bitcoin Core's `estimatesmartfee` ignores the mempool backlog: it reads recent block fees, and
/// it raises the result to the node's mempool minimum. Its fastest answer is a lagging two-block
/// economical estimate; see [`FeeSource::next_block_rate`]. On a public network with a varied
/// mempool the `MempoolExplorerFeeSource` follows a rising backlog sooner.
#[derive(Debug)]
struct BitcoindFeeSource {
    client: Arc<dyn FeeRateRpc>,
}

#[async_trait]
impl FeeSource for BitcoindFeeSource {
    /// One `estimatesmartfee(1)` round trip, floored at `MIN_SOURCE_FEE_RATE`.
    async fn next_block_rate(&self) -> Result<FeeRate, FeeSourceError> {
        self.client
            .estimate_smart_fee(1)
            .await?
            .map(|rate| rate.max(MIN_SOURCE_FEE_RATE))
            .ok_or(FeeSourceError::NoEstimate)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Mempool explorer (mempool.space-compatible)
// ────────────────────────────────────────────────────────────────────────────

/// The part of a mempool.space-compatible `/api/v1/fees/recommended` response that the source
/// reads. `fastestFee` is the tier designed to confirm in the next block.
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
struct RecommendedFees {
    #[serde(rename = "fastestFee")]
    fastest_fee: u64,
}

/// Total timeout of one explorer request. `reqwest` defaults to none, and the fallback to Bitcoin
/// Core only triggers on an error result, not on a never-resolving future. Recommended-fees
/// responses are small, hosted on a CDN, and arrive in well under a second.
const EXPLORER_TIMEOUT: Duration = Duration::from_secs(10);

/// Fee source backed by a mempool.space-compatible explorer's recommended-fees endpoint, with
/// a Bitcoin Core fallback.
///
/// Falls back to the wrapped `BitcoindFeeSource` on any HTTP error, non-2xx status, decode
/// failure, or rate that overflows [`FeeRate`]. The fallback error replaces the mempool error in
/// the result; the mempool error is only logged. A downed mempool explorer must never block tx
/// publishing.
#[derive(Debug)]
struct MempoolExplorerFeeSource {
    http: reqwest::Client,
    recommended_fees_url: Url,
    fallback: BitcoindFeeSource,
}

impl MempoolExplorerFeeSource {
    /// Creates a new source that GETs `recommended_fees_url` and reads its fastest tier.
    fn new(recommended_fees_url: Url, fallback: BitcoindFeeSource) -> Result<Self, FeeConfigError> {
        let http = reqwest::Client::builder()
            .timeout(EXPLORER_TIMEOUT)
            .build()
            .map_err(FeeConfigError::HttpClient)?;
        Ok(Self {
            http,
            recommended_fees_url,
            fallback,
        })
    }

    async fn fetch_recommended(&self) -> Result<RecommendedFees, ExplorerError> {
        let response = self
            .http
            .get(self.recommended_fees_url.clone())
            .send()
            .await
            .map_err(ExplorerError::Http)?
            .error_for_status()
            .map_err(ExplorerError::Http)?;
        response
            .json::<RecommendedFees>()
            .await
            .map_err(ExplorerError::Decode)
    }
}

/// Joins the recommended-fees path onto `base_url`, e.g. `https://mempool.space/signet` or
/// `https://mempool.space` for mainnet.
///
/// A scheme other than `http` or `https` is an error: `reqwest` would refuse it on every read, and
/// the Core fallback would hide that.
fn recommended_fees_url(mut base_url: Url) -> Result<Url, FeeConfigError> {
    if !matches!(base_url.scheme(), "http" | "https") {
        return Err(FeeConfigError::InvalidExplorerUrl(format!(
            "unsupported scheme in {base_url}"
        )));
    }
    // Ensure the base URL has a trailing slash so `Url::join` treats it as a directory.
    // Without this, `join("api/v1/fees/recommended")` would replace the last path segment.
    if !base_url.path().ends_with('/') {
        let path = format!("{}/", base_url.path());
        base_url.set_path(&path);
    }
    base_url
        .join("api/v1/fees/recommended")
        .map_err(|e| FeeConfigError::InvalidExplorerUrl(format!("{e:?}")))
}

#[async_trait]
impl FeeSource for MempoolExplorerFeeSource {
    async fn next_block_rate(&self) -> Result<FeeRate, FeeSourceError> {
        let rate = self
            .fetch_recommended()
            .await
            .and_then(|fees| explorer_rate(fees.fastest_fee));
        match rate {
            Ok(rate) => Ok(rate),
            Err(e) => {
                warn!(error = %e, "mempool explorer fee lookup failed; falling back to bitcoind");
                self.fallback.next_block_rate().await
            }
        }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Fixed (for tests / manual overrides)
// ────────────────────────────────────────────────────────────────────────────

/// Fee source that returns a constant rate, regardless of network conditions.
///
/// Intended for tests and emergency manual overrides. The source itself clamps nothing.
#[derive(Debug)]
struct FixedFeeSource(FeeRate);

#[async_trait]
impl FeeSource for FixedFeeSource {
    async fn next_block_rate(&self) -> Result<FeeRate, FeeSourceError> {
        Ok(self.0)
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Config + builder
// ────────────────────────────────────────────────────────────────────────────

/// Serializable operator-side configuration that selects a [`FeeSource`] policy.
///
/// Built into a concrete source at startup via [`FeeSourceConfig::build`], taking the operator's
/// Bitcoin Core RPC client as the fallback source for the mempool variant.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FeeSourceConfig {
    /// Query Bitcoin Core's `estimatesmartfee(1)` directly.
    BitcoinCore,
    /// Query a mempool.space-compatible explorer's `/api/v1/fees/recommended` endpoint, with
    /// Bitcoin Core as the fallback if the explorer is unreachable.
    MempoolExplorer {
        /// Base URL, e.g. `https://mempool.space/signet` or `https://mempool.space`.
        base_url: Url,
    },
    /// Return a constant rate. Intended for tests and emergency manual overrides.
    Fixed {
        /// sat/vB.
        fee_rate: u64,
    },
}

/// A [`FeeSourceConfig`] with every value checked.
enum ParsedFeeSource {
    BitcoinCore,
    MempoolExplorer { recommended_fees_url: Url },
    Fixed(FeeRate),
}

impl FeeSourceConfig {
    fn parse(&self) -> Result<ParsedFeeSource, FeeConfigError> {
        match self {
            Self::BitcoinCore => Ok(ParsedFeeSource::BitcoinCore),
            Self::MempoolExplorer { base_url } => Ok(ParsedFeeSource::MempoolExplorer {
                recommended_fees_url: recommended_fees_url(base_url.clone())?,
            }),
            Self::Fixed { fee_rate } => FeeRate::from_sat_per_vb(*fee_rate)
                .map(ParsedFeeSource::Fixed)
                .ok_or(FeeConfigError::InvalidFixedRate(*fee_rate)),
        }
    }

    /// Rejects a config that [`Self::build`] cannot build. This needs no RPC client, so the startup
    /// checks run it before any service starts.
    pub fn validate(&self) -> Result<(), FeeConfigError> {
        self.parse().map(|_| ())
    }

    /// Constructs the configured [`FeeSource`] from this config + a Bitcoin Core RPC client.
    ///
    /// `bitcoind` is used as the primary source for [`FeeSourceConfig::BitcoinCore`], and as the
    /// fallback for [`FeeSourceConfig::MempoolExplorer`].
    pub fn build(
        &self,
        bitcoind: Arc<dyn FeeRateRpc>,
    ) -> Result<Arc<dyn FeeSource>, FeeConfigError> {
        Ok(match self.parse()? {
            ParsedFeeSource::BitcoinCore => Arc::new(BitcoindFeeSource { client: bitcoind }),
            ParsedFeeSource::MempoolExplorer {
                recommended_fees_url,
            } => Arc::new(MempoolExplorerFeeSource::new(
                recommended_fees_url,
                BitcoindFeeSource { client: bitcoind },
            )?),
            ParsedFeeSource::Fixed(rate) => Arc::new(FixedFeeSource(rate)),
        })
    }
}

impl Default for FeeSourceConfig {
    /// Defaults to Bitcoin Core.
    fn default() -> Self {
        Self::BitcoinCore
    }
}

// ────────────────────────────────────────────────────────────────────────────
// minimum fee rates
// ────────────────────────────────────────────────────────────────────────────

/// Floor for every network-backed source's reported rate. Core's default `minrelaytxfee` is
/// 0.1 sat/vB, so this floor sits above it and keeps relay through peers with an older default.
/// Sources can legitimately report below it (a quiet mempool, an explorer's economy tier at 0), so
/// they clamp up.
const MIN_SOURCE_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(1);

// ────────────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────────────

/// Converts an explorer rate, floored at `MIN_SOURCE_FEE_RATE`. A rate that overflows [`FeeRate`]
/// is an error: the explorer is wrong, and only the fallback can say what the market is.
fn explorer_rate(raw_sat_per_vb: u64) -> Result<FeeRate, ExplorerError> {
    FeeRate::from_sat_per_vb(raw_sat_per_vb)
        .map(|rate| rate.max(MIN_SOURCE_FEE_RATE))
        .ok_or(ExplorerError::RateOverflow(raw_sat_per_vb))
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
        rate: ClientResult<Option<FeeRate>>,
    }

    impl MockFeeRateRpc {
        fn returning(sat_per_vb: u64) -> Self {
            Self {
                rate: Ok(FeeRate::from_sat_per_vb(sat_per_vb)),
            }
        }

        fn failing() -> Self {
            Self {
                rate: Err(ClientError::Request("boom".to_string())),
            }
        }

        /// `estimatesmartfee` succeeded but produced no estimate (insufficient data — fresh
        /// regtest, early signet).
        fn returning_none() -> Self {
            Self { rate: Ok(None) }
        }
    }

    #[async_trait]
    impl FeeRateRpc for MockFeeRateRpc {
        async fn estimate_smart_fee(&self, _conf_target: u16) -> ClientResult<Option<FeeRate>> {
            self.rate.clone()
        }
    }

    fn bitcoind(rpc: MockFeeRateRpc) -> BitcoindFeeSource {
        BitcoindFeeSource {
            client: Arc::new(rpc),
        }
    }

    fn recommended_fees_body(fastest: u64) -> serde_json::Value {
        serde_json::json!({
            "fastestFee": fastest,
            "halfHourFee": 7,
            "hourFee": 5,
            "economyFee": 3,
            "minimumFee": 2,
        })
    }

    async fn explorer_serving(body: ResponseTemplate) -> MockServer {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/fees/recommended"))
            .respond_with(body)
            .mount(&server)
            .await;
        server
    }

    fn explorer(server: &MockServer, fallback: MockFeeRateRpc) -> MempoolExplorerFeeSource {
        MempoolExplorerFeeSource::new(
            recommended_fees_url(Url::parse(&server.uri()).unwrap()).unwrap(),
            bitcoind(fallback),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn bitcoind_floors_zero_to_one() {
        let source = bitcoind(MockFeeRateRpc::returning(0));
        assert_eq!(
            source.next_block_rate().await.unwrap(),
            FeeRate::from_sat_per_vb(1).unwrap()
        );
    }

    /// bitcoind saying "no idea" is distinct from a zero estimate, and the memo needs to tell it
    /// from a real rate.
    #[tokio::test]
    async fn bitcoind_reports_a_missing_estimate() {
        let source = bitcoind(MockFeeRateRpc::returning_none());
        assert!(matches!(
            source.next_block_rate().await,
            Err(FeeSourceError::NoEstimate)
        ));
    }

    #[tokio::test]
    async fn bitcoind_propagates_rpc_error() {
        let source = bitcoind(MockFeeRateRpc::failing());
        let err = source.next_block_rate().await.unwrap_err();
        assert!(
            matches!(err, FeeSourceError::Bitcoind(_)),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn mempool_reads_the_fastest_tier() {
        let server =
            explorer_serving(ResponseTemplate::new(200).set_body_json(recommended_fees_body(10)))
                .await;
        let source = explorer(&server, MockFeeRateRpc::failing());
        assert_eq!(
            source.next_block_rate().await.unwrap(),
            FeeRate::from_sat_per_vb(10).unwrap()
        );
    }

    /// Any explorer error falls back to Core, and the explorer error is absorbed.
    #[tokio::test]
    async fn mempool_falls_back_to_bitcoind_on_an_error() {
        let server = explorer_serving(ResponseTemplate::new(500)).await;
        let source = explorer(&server, MockFeeRateRpc::returning(4));
        assert_eq!(
            source.next_block_rate().await.unwrap(),
            FeeRate::from_sat_per_vb(4).unwrap()
        );
    }

    #[tokio::test]
    async fn mempool_and_fallback_both_fail() {
        let server = explorer_serving(ResponseTemplate::new(503)).await;
        let source = explorer(&server, MockFeeRateRpc::failing());
        // Mempool error is absorbed; surfaced error is from the bitcoind fallback.
        let err = source.next_block_rate().await.unwrap_err();
        assert!(
            matches!(err, FeeSourceError::Bitcoind(_)),
            "unexpected error: {err}"
        );
    }

    #[tokio::test]
    async fn mempool_base_url_without_trailing_slash_works() {
        // mempool.space/signet style — must still resolve to .../signet/api/v1/fees/recommended.
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/signet/api/v1/fees/recommended"))
            .respond_with(ResponseTemplate::new(200).set_body_json(recommended_fees_body(12)))
            .mount(&server)
            .await;

        let base = Url::parse(&format!("{}/signet", server.uri())).unwrap();
        let url = recommended_fees_url(base).unwrap();
        let source =
            MempoolExplorerFeeSource::new(url, bitcoind(MockFeeRateRpc::failing())).unwrap();
        assert_eq!(
            source.next_block_rate().await.unwrap(),
            FeeRate::from_sat_per_vb(12).unwrap()
        );
    }

    /// An explorer rate that overflows [`FeeRate`] says nothing about the market, so Core answers
    /// for it. Reading it as the floor would price every target at 1 sat/vB.
    #[tokio::test]
    async fn mempool_fallback_on_a_rate_that_overflows() {
        let server = explorer_serving(
            ResponseTemplate::new(200).set_body_json(recommended_fees_body(u64::MAX)),
        )
        .await;
        let source = explorer(&server, MockFeeRateRpc::returning(6));
        assert_eq!(
            source.next_block_rate().await.unwrap(),
            FeeRate::from_sat_per_vb(6).unwrap()
        );
    }

    #[test]
    fn explorer_rate_floors_zero() {
        assert_eq!(explorer_rate(0).unwrap(), MIN_SOURCE_FEE_RATE);
    }

    #[test]
    fn validate_rejects_a_fixed_rate_that_overflows() {
        let cfg = FeeSourceConfig::Fixed { fee_rate: u64::MAX };
        assert!(matches!(
            cfg.validate(),
            Err(FeeConfigError::InvalidFixedRate(u64::MAX))
        ));
        assert!(matches!(
            cfg.build(Arc::new(MockFeeRateRpc::returning(1))),
            Err(FeeConfigError::InvalidFixedRate(u64::MAX))
        ));
    }

    #[test]
    fn validate_rejects_an_explorer_url_that_reqwest_refuses() {
        let cfg = FeeSourceConfig::MempoolExplorer {
            base_url: "file:///fees".parse().unwrap(),
        };
        assert!(matches!(
            cfg.validate(),
            Err(FeeConfigError::InvalidExplorerUrl(_))
        ));
    }

    #[test]
    fn fee_source_config_parses_toml() {
        let cfg: FeeSourceConfig = toml::from_str(r#"kind = "bitcoin_core""#).unwrap();
        assert_eq!(cfg, FeeSourceConfig::BitcoinCore);
        let cfg: FeeSourceConfig = toml::from_str(
            r#"
            kind = "mempool_explorer"
            base_url = "https://mempool.space/signet"
        "#,
        )
        .unwrap();
        assert!(matches!(cfg, FeeSourceConfig::MempoolExplorer { .. }));
        let cfg: FeeSourceConfig = toml::from_str(
            r#"
            kind = "fixed"
            fee_rate = 3
        "#,
        )
        .unwrap();
        assert_eq!(cfg, FeeSourceConfig::Fixed { fee_rate: 3 });
    }
}
