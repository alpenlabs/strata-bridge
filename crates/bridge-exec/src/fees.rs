//! Fee-rate sources for bridge transactions.
//!
//! Provides three implementations of [`btc_tracker::cpfp::CpfpFeeSource`]:
//!
//! * [`BitcoindFeeSource`] — queries `estimatesmartfee` on the local Bitcoin Core RPC.
//! * [`MempoolExplorerFeeSource`] — queries a mempool.space-compatible explorer's
//!   `/api/v1/fees/recommended` endpoint; falls back to a wrapped [`BitcoindFeeSource`] on any HTTP
//!   or decode failure so a downed mempool explorer never blocks tx publishing.
//! * [`FixedFeeSource`] — returns a constant rate (tests, manual overrides).
//!
//! The network-backed sources clamp their reported rate to [`MIN_SOURCE_FEE_RATE`];
//! [`FixedFeeSource`] deliberately returns the configured rate verbatim (it is the manual
//! escape hatch, so it must be able to say exactly what the operator asked for).
//!
//! The orchestrator builds the configured source via [`FeeSourceConfig::build`] and wraps it in
//! a [`btc_tracker::cpfp::CachedFeeSource`], which refreshes in the background and is shared by
//! both the executors (per-tx-build fee estimates) and the tx-driver's CPFP/RBF bump loop — so
//! neither hits the network per call.

// `MIN_SOURCE_FEE_RATE` is referenced from the public module/item docs above; allowing
// `private_intra_doc_links` here keeps the references resolvable without exporting the const.
#![allow(rustdoc::private_intra_doc_links)]

use std::{
    sync::{Arc, LazyLock},
    time::Duration,
};

use async_trait::async_trait;
use bitcoin::FeeRate;
use bitcoind_async_client::{ClientResult, traits::Reader};
use btc_tracker::cpfp::{
    CachedFeeSource, CpfpFeeSource, FeeSourceError as CpfpFeeSourceError, FeeTarget, TargetRates,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::warn;
use url::Url;

use crate::errors::ExecutorError;

/// Narrow trait covering only the RPC surface the fee source needs.
///
/// Auto-implemented for every [`Reader`], and tests can implement it directly without modeling
/// the dozens of other [`Reader`] methods. The fallback path only needs `estimate_smart_fee`,
/// so the trait stays single-method on purpose.
#[async_trait]
pub trait FeeRateRpc: Send + Sync + std::fmt::Debug {
    /// See [`Reader::estimate_smart_fee`]. `None` means bitcoind had insufficient data to
    /// produce an estimate (fresh regtest, early signet), which callers treat as "fall back to
    /// the floor" rather than as an error.
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

/// Errors produced by [`CpfpFeeSource`] implementations.
#[derive(Debug, Error)]
pub enum FeeSourceError {
    /// Bitcoin Core RPC reported an error.
    #[error("bitcoind: {0}")]
    Bitcoind(#[from] bitcoind_async_client::error::ClientError),
    /// The mempool explorer call failed (HTTP error, non-2xx, or timeout).
    ///
    /// Never surfaced from `estimate()`: the explorer source always wraps a Bitcoin Core
    /// fallback, so this is logged (`warn`) and absorbed. If the fallback then fails too,
    /// callers see the *bitcoind* error, not this one.
    #[error("mempool explorer: {0}")]
    MempoolHttp(String),
    /// The mempool explorer response could not be decoded as the expected JSON shape.
    ///
    /// Never surfaced from `estimate()` — same absorption story as [`Self::MempoolHttp`].
    #[error("mempool explorer decode: {0}")]
    MempoolDecode(String),
    /// The configured mempool explorer URL is malformed.
    #[error("invalid mempool explorer url: {0}")]
    InvalidConfig(String),
    /// A configured confirmation target is outside Bitcoin Core's accepted `1..=1008` range.
    #[error("{field} = {target} is outside Bitcoin Core's estimatesmartfee range (1..=1008)")]
    InvalidConfTarget {
        /// Which config field carried the bad value.
        field: &'static str,
        /// The rejected value.
        target: u16,
    },
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
    ///
    /// `conf_target` must be in `1..=1008` (Bitcoin Core rejects everything else).
    /// [`FeeSourceConfig::build`] validates before it constructs; a direct caller owns
    /// that check itself.
    ///
    /// `conf_target` controls the [`FeeTarget::Standard`] slot only; the
    /// [`FeeTarget::NextBlock`] slot always queries `estimatesmartfee(1)`.
    pub const fn new(client: Arc<R>, conf_target: u16) -> Self {
        Self {
            client,
            conf_target,
        }
    }

    /// One `estimatesmartfee` round trip for `target`, floored at [`MIN_SOURCE_FEE_RATE`].
    async fn estimate_target(&self, target: FeeTarget) -> Result<FeeRate, CpfpFeeSourceError> {
        let conf_target = match target {
            FeeTarget::Standard => self.conf_target,
            FeeTarget::NextBlock => 1,
        };
        let rate = self
            .client
            .estimate_smart_fee(conf_target)
            .await
            .map_err(|e| CpfpFeeSourceError(FeeSourceError::Bitcoind(e).to_string()))?;
        let rate = match rate {
            Some(rate) => rate,
            None => {
                // `estimatesmartfee` reports no estimate when it lacks data — normal on a
                // fresh regtest, but on a real network it means the node is cold, pruned of
                // fee history, or running `-blocksonly`. Substituting the floor keeps the
                // bridge publishing either way, but do it LOUDLY: without this log a
                // misconfigured node is indistinguishable from a genuinely calm mempool,
                // and every bump quietly targets the minimum forever.
                warn!(
                    conf_target,
                    "estimatesmartfee returned no estimate; falling back to the floor fee rate"
                );
                MIN_SOURCE_FEE_RATE
            }
        };
        Ok(rate.max(MIN_SOURCE_FEE_RATE))
    }
}

impl<R: FeeRateRpc> CpfpFeeSource for BitcoindFeeSource<R> {
    async fn estimate(&self, target: FeeTarget) -> Result<FeeRate, CpfpFeeSourceError> {
        self.estimate_target(target).await
    }

    async fn estimate_all(&self) -> Result<TargetRates, CpfpFeeSourceError> {
        // Dedupe when the configured standard tier is already the next-block tier:
        // two `estimatesmartfee(1)` round trips would buy one answer.
        let next_block = self.estimate_target(FeeTarget::NextBlock).await?;
        let standard = if self.conf_target == 1 {
            next_block
        } else {
            self.estimate_target(FeeTarget::Standard).await?
        };
        Ok(TargetRates {
            standard,
            next_block,
        })
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
    /// `policy` controls the [`FeeTarget::Standard`] slot only; the
    /// [`FeeTarget::NextBlock`] slot always selects the fastest tier.
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

    /// Maps a [`FeeTarget`] onto the explorer tier it consumes. Next-block is always the
    /// endpoint's `fastestFee` tier, whatever the configured policy is.
    const fn tier_for(target: FeeTarget, configured: MempoolFeePolicy) -> MempoolFeePolicy {
        match target {
            FeeTarget::Standard => configured,
            FeeTarget::NextBlock => MempoolFeePolicy::Fastest,
        }
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

impl<R: FeeRateRpc> CpfpFeeSource for MempoolExplorerFeeSource<R> {
    async fn estimate(&self, target: FeeTarget) -> Result<FeeRate, CpfpFeeSourceError> {
        match self.fetch_recommended().await {
            Ok(fees) => Ok(clamp_to_min(
                fees.select(Self::tier_for(target, self.policy)),
            )),
            Err(e) => {
                warn!(error = %e, "mempool explorer fee lookup failed; falling back to bitcoind");
                self.fallback.estimate(target).await
            }
        }
    }

    /// One HTTP call feeds both slots — the endpoint returns every tier at once.
    async fn estimate_all(&self) -> Result<TargetRates, CpfpFeeSourceError> {
        match self.fetch_recommended().await {
            Ok(fees) => Ok(TargetRates {
                standard: clamp_to_min(
                    fees.select(Self::tier_for(FeeTarget::Standard, self.policy)),
                ),
                next_block: clamp_to_min(
                    fees.select(Self::tier_for(FeeTarget::NextBlock, self.policy)),
                ),
            }),
            Err(e) => {
                warn!(error = %e, "mempool explorer fee lookup failed; falling back to bitcoind");
                self.fallback.estimate_all().await
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

impl CpfpFeeSource for FixedFeeSource {
    async fn estimate(&self, _target: FeeTarget) -> Result<FeeRate, CpfpFeeSourceError> {
        Ok(self.0)
    }

    async fn estimate_all(&self) -> Result<TargetRates, CpfpFeeSourceError> {
        Ok(TargetRates {
            standard: self.0,
            next_block: self.0,
        })
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Config + builder
// ────────────────────────────────────────────────────────────────────────────

/// The concrete [`CpfpFeeSource`] selected by a [`FeeSourceConfig`].
///
/// A single enum (rather than `Box<dyn CpfpFeeSource>`) keeps the AFIT [`CpfpFeeSource`] trait
/// usable without a boxed-future shim: the orchestrator wraps this in a
/// [`btc_tracker::cpfp::CachedFeeSource`] and shares that one cache with both the executors and
/// the CPFP bump loop.
#[derive(Debug)]
pub enum ConfiguredFeeSource<R> {
    /// Bitcoin Core `estimatesmartfee`.
    Bitcoind(BitcoindFeeSource<R>),
    /// mempool.space-compatible explorer with a Bitcoin Core fallback.
    Mempool(MempoolExplorerFeeSource<R>),
    /// Constant rate (tests / manual overrides).
    Fixed(FixedFeeSource),
}

impl<R: FeeRateRpc> CpfpFeeSource for ConfiguredFeeSource<R> {
    async fn estimate(&self, target: FeeTarget) -> Result<FeeRate, CpfpFeeSourceError> {
        match self {
            Self::Bitcoind(s) => s.estimate(target).await,
            Self::Mempool(s) => s.estimate(target).await,
            Self::Fixed(s) => s.estimate(target).await,
        }
    }

    async fn estimate_all(&self) -> Result<TargetRates, CpfpFeeSourceError> {
        match self {
            Self::Bitcoind(s) => s.estimate_all().await,
            Self::Mempool(s) => s.estimate_all().await,
            Self::Fixed(s) => s.estimate_all().await,
        }
    }
}

/// Serializable operator-side configuration that selects a [`CpfpFeeSource`] policy.
///
/// Built into a concrete [`ConfiguredFeeSource`] at startup via [`FeeSourceConfig::build`],
/// taking the operator's Bitcoin Core RPC client as the fallback source for the mempool variant.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FeeSourceConfig {
    /// Query Bitcoin Core's `estimatesmartfee(conf_target)` directly.
    BitcoinCore {
        /// Block confirmation target passed to `estimatesmartfee` for `Standard` estimates.
        /// The `NextBlock` target always queries conf target 1.
        conf_target: u16,
    },
    /// Query a mempool.space-compatible explorer's `/api/v1/fees/recommended` endpoint, with
    /// Bitcoin Core as the fallback if the explorer is unreachable.
    MempoolExplorer {
        /// Base URL, e.g. `https://mempool.space/signet` or `https://mempool.space`.
        base_url: Url,
        /// The tier of the recommended-fees response to use for `Standard` estimates. The
        /// `NextBlock` target always uses the fastest tier.
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

/// Bitcoin Core rejects `estimatesmartfee` confirmation targets outside `1..=1008`.
const MAX_CONF_TARGET: u16 = 1008;

/// Rejects a confirmation target that Bitcoin Core's `estimatesmartfee` will refuse.
///
/// The two variants fail at very different times without this check. `BitcoinCore` fails at
/// boot — the cached source's first synchronous refresh propagates the RPC error and the
/// orchestrator aborts, with a cryptic message. `MempoolExplorer` is the dangerous one: a
/// working explorer masks a broken `fallback_conf_target` entirely, every later refresh
/// through the fallback fails, and the cache serves the last explorer quote forever — the
/// misconfiguration surfaces on the day the fallback is first needed, which is the worst
/// possible time to discover it.
const fn validate_conf_target(target: u16, field: &'static str) -> Result<(), FeeSourceError> {
    if target == 0 || target > MAX_CONF_TARGET {
        return Err(FeeSourceError::InvalidConfTarget { field, target });
    }
    Ok(())
}

impl FeeSourceConfig {
    /// Constructs the configured [`CpfpFeeSource`] from this config + a Bitcoin Core RPC client.
    ///
    /// `bitcoind` is used as the primary source for [`FeeSourceConfig::BitcoinCore`], and as the
    /// fallback for [`FeeSourceConfig::MempoolExplorer`].
    pub fn build<R>(self, bitcoind: Arc<R>) -> Result<ConfiguredFeeSource<R>, FeeSourceError>
    where
        R: FeeRateRpc + 'static,
    {
        match self {
            Self::BitcoinCore { conf_target } => {
                validate_conf_target(conf_target, "conf_target")?;
                Ok(ConfiguredFeeSource::Bitcoind(BitcoindFeeSource::new(
                    bitcoind,
                    conf_target,
                )))
            }
            Self::MempoolExplorer {
                base_url,
                policy,
                fallback_conf_target,
            } => {
                validate_conf_target(fallback_conf_target, "fallback_conf_target")?;
                let fallback = BitcoindFeeSource::new(bitcoind, fallback_conf_target);
                Ok(ConfiguredFeeSource::Mempool(MempoolExplorerFeeSource::new(
                    base_url, policy, fallback,
                )?))
            }
            Self::Fixed { fee_rate } => {
                let source = FixedFeeSource::from_sat_per_vb(fee_rate).ok_or_else(|| {
                    FeeSourceError::InvalidConfig(format!(
                        "fixed fee rate {fee_rate} sat/vB exceeds FeeRate's u64 sat/kwu range"
                    ))
                })?;
                Ok(ConfiguredFeeSource::Fixed(source))
            }
        }
    }
}

impl Default for FeeSourceConfig {
    /// Defaults to Bitcoin Core with `conf_target = 1`.
    fn default() -> Self {
        Self::BitcoinCore { conf_target: 1 }
    }
}

// ────────────────────────────────────────────────────────────────────────────
// minimum fee rates
// ────────────────────────────────────────────────────────────────────────────

/// Floor for every network-backed source's reported rate — Core's default `minrelaytxfee`
/// expressed in sat/vB. Sources can legitimately report below it (a quiet mempool, an
/// explorer's economy tier at 0) or nothing at all (`estimatesmartfee` with insufficient
/// data); targeting below min-relay would leave the resulting transaction or package
/// unrelayable, so those sources clamp up to this floor.
const MIN_SOURCE_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(1);

/// Minimum rate at which the bridge broadcasts a *wallet-funded* transaction (withdrawal
/// fulfillment, stake funding). The configured source already clamps to [`MIN_SOURCE_FEE_RATE`];
/// this is the higher bridge-policy floor that keeps these v3 (TRUC) transactions relayable even
/// when the source reports a lower rate.
///
/// Deliberately a standalone constant, not a reuse of `strata_bridge_tx_graph::fee::FEE_RATE`:
/// that constant is the rate presigned transactions are *built at*, not a minimum, and is slated
/// for removal once CPFP fully supersedes the static-fee scheme.
pub const MIN_WALLET_TX_FEE_RATE: FeeRate = FeeRate::from_sat_per_vb_unchecked(2);

// ────────────────────────────────────────────────────────────────────────────
// helpers
// ────────────────────────────────────────────────────────────────────────────

fn clamp_to_min(raw_sat_per_vb: u64) -> FeeRate {
    FeeRate::from_sat_per_vb(raw_sat_per_vb)
        .unwrap_or(MIN_SOURCE_FEE_RATE)
        .max(MIN_SOURCE_FEE_RATE)
}

/// Fee rate for a *wallet-funded* transaction (claim-funding refill, stake funding,
/// withdrawal fulfillment): the shared source's current cached estimate, floored at
/// [`MIN_WALLET_TX_FEE_RATE`] so the resulting v3 (TRUC) transaction stays relayable, and
/// rejected outright when it exceeds the operator's `maximum_fee_rate` policy.
///
/// Presigned bridge transactions do NOT use this — their fee is fixed at
/// `strata_bridge_tx_graph::fee::FEE_RATE` by construction and is raised after the fact by
/// the CPFP bump loop instead.
pub(crate) fn wallet_tx_fee_rate(
    fee_source: &CachedFeeSource,
    maximum_fee_rate: FeeRate,
) -> Result<FeeRate, ExecutorError> {
    // `try_current`, not `current`: a duty that prices from a frozen quote broadcasts at
    // whatever the market was when the source died. The error aborts the duty, and the
    // retry succeeds after the source recovers. `Standard`: wallet-funded transactions are
    // not time-critical and do not pay the next-block premium tier.
    let fee_rate = fee_source
        .try_current(FeeTarget::Standard)?
        .max(MIN_WALLET_TX_FEE_RATE);
    if fee_rate > maximum_fee_rate {
        return Err(ExecutorError::FeeRateTooHigh {
            fee_rate,
            max: maximum_fee_rate,
        });
    }
    Ok(fee_rate)
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

        /// `estimatesmartfee` succeeded but produced no estimate (insufficient data —
        /// fresh regtest, early signet, `-blocksonly` node).
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

    /// [`MockFeeRateRpc`] variant that records the conf target of every `estimatesmartfee`
    /// call, for asserting the [`FeeTarget`] → conf-target mapping.
    #[derive(Debug)]
    struct CapturingFeeRateRpc {
        rate: ClientResult<Option<FeeRate>>,
        conf_targets: std::sync::Mutex<Vec<u16>>,
    }

    #[async_trait]
    impl FeeRateRpc for CapturingFeeRateRpc {
        async fn estimate_smart_fee(&self, conf_target: u16) -> ClientResult<Option<FeeRate>> {
            self.conf_targets.lock().unwrap().push(conf_target);
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
        let rate = source.estimate(FeeTarget::Standard).await.unwrap();
        assert_eq!(rate, FeeRate::from_sat_per_vb(5).unwrap());
    }

    #[tokio::test]
    async fn bitcoind_maps_targets_to_conf_targets() {
        let capturing = Arc::new(CapturingFeeRateRpc {
            rate: Ok(FeeRate::from_sat_per_vb(5)),
            conf_targets: std::sync::Mutex::new(Vec::new()),
        });
        let source = BitcoindFeeSource::new(capturing.clone(), 3);
        source.estimate(FeeTarget::NextBlock).await.unwrap();
        source.estimate(FeeTarget::Standard).await.unwrap();
        // NextBlock always queries conf target 1; Standard queries the configured target.
        assert_eq!(*capturing.conf_targets.lock().unwrap(), vec![1, 3]);
    }

    #[tokio::test]
    async fn bitcoind_estimate_all_dedupes_when_standard_is_next_block() {
        let capturing = Arc::new(CapturingFeeRateRpc {
            rate: Ok(FeeRate::from_sat_per_vb(5)),
            conf_targets: std::sync::Mutex::new(Vec::new()),
        });
        let source = BitcoindFeeSource::new(capturing.clone(), 1);
        let rates = source.estimate_all().await.unwrap();
        // One round trip fills both slots when the configured standard tier is already 1.
        assert_eq!(*capturing.conf_targets.lock().unwrap(), vec![1]);
        assert_eq!(rates.standard, rates.next_block);
    }

    #[tokio::test]
    async fn bitcoind_floors_zero_to_one() {
        let source = BitcoindFeeSource::new(Arc::new(MockFeeRateRpc::returning(0)), 1);
        let rate = source.estimate(FeeTarget::Standard).await.unwrap();
        assert_eq!(rate, FeeRate::from_sat_per_vb(1).unwrap());
    }

    /// The `Ok(None)` arm is distinct from a zero estimate: bitcoind is saying "no idea",
    /// not "zero". It must resolve to the floor, not an error — a cold node must not block
    /// publishing.
    #[tokio::test]
    async fn bitcoind_floors_missing_estimate_to_one() {
        let source = BitcoindFeeSource::new(Arc::new(MockFeeRateRpc::returning_none()), 1);
        let rate = source.estimate(FeeTarget::Standard).await.unwrap();
        assert_eq!(rate, FeeRate::from_sat_per_vb(1).unwrap());
    }

    #[tokio::test]
    async fn bitcoind_propagates_rpc_error() {
        let source = BitcoindFeeSource::new(Arc::new(MockFeeRateRpc::failing()), 1);
        let err = source.estimate(FeeTarget::Standard).await.unwrap_err();
        assert!(err.0.contains("bitcoind"), "unexpected error: {err}");
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
        let rate = source.estimate(FeeTarget::Standard).await.unwrap();
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
        let rate = source.estimate(FeeTarget::Standard).await.unwrap();
        assert_eq!(rate, FeeRate::from_sat_per_vb(3).unwrap());
    }

    /// Pins the `FeeTarget`-to-tier mapping: `Standard` reads the configured policy (economy
    /// here) and `NextBlock` always reads the fastest tier. A regression mapping `NextBlock`
    /// to the configured policy would leave this suite green while pricing CPFP children at
    /// the slower tier.
    #[tokio::test]
    async fn mempool_maps_targets_to_tiers() {
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
        assert_eq!(
            source.estimate(FeeTarget::Standard).await.unwrap(),
            FeeRate::from_sat_per_vb(3).unwrap()
        );
        assert_eq!(
            source.estimate(FeeTarget::NextBlock).await.unwrap(),
            FeeRate::from_sat_per_vb(10).unwrap()
        );
        let rates = source.estimate_all().await.unwrap();
        assert_eq!(rates.standard, FeeRate::from_sat_per_vb(3).unwrap());
        assert_eq!(rates.next_block, FeeRate::from_sat_per_vb(10).unwrap());
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
        let rate = source.estimate(FeeTarget::Standard).await.unwrap();
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
        let rate = source.estimate(FeeTarget::Standard).await.unwrap();
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
        let err = source.estimate(FeeTarget::Standard).await.unwrap_err();
        assert!(err.0.contains("bitcoind"), "unexpected error: {err}");
    }

    #[tokio::test]
    async fn fixed_source_returns_configured_rate() {
        let source = FixedFeeSource::from_sat_per_vb(7).unwrap();
        let rate = source.estimate(FeeTarget::Standard).await.unwrap();
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
        let rate = source.estimate(FeeTarget::Standard).await.unwrap();
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

    /// An out-of-range `fallback_conf_target` must fail at build time, not on the day the
    /// fallback is first exercised. A working explorer masks the broken fallback entirely:
    /// every later refresh through it fails, the cache serves the last explorer quote
    /// forever, and the operator learns about the typo during the outage the fallback
    /// existed for.
    #[test]
    fn build_rejects_out_of_range_conf_targets() {
        for bad in [0u16, 1009] {
            let cfg = FeeSourceConfig::MempoolExplorer {
                base_url: "https://mempool.space".parse().unwrap(),
                policy: MempoolFeePolicy::Fastest,
                fallback_conf_target: bad,
            };
            let err = cfg.build(Arc::new(MockFeeRateRpc::returning(1)));
            assert!(
                matches!(
                    err,
                    Err(FeeSourceError::InvalidConfTarget {
                        field: "fallback_conf_target",
                        target,
                    }) if target == bad
                ),
                "fallback_conf_target = {bad} must be rejected at build"
            );

            let cfg = FeeSourceConfig::BitcoinCore { conf_target: bad };
            let err = cfg.build(Arc::new(MockFeeRateRpc::returning(1)));
            assert!(
                matches!(
                    err,
                    Err(FeeSourceError::InvalidConfTarget {
                        field: "conf_target",
                        target,
                    }) if target == bad
                ),
                "conf_target = {bad} must be rejected at build"
            );
        }

        // The range boundaries themselves are valid, for both variants.
        for good in [1u16, 1008] {
            assert!(
                FeeSourceConfig::BitcoinCore { conf_target: good }
                    .build(Arc::new(MockFeeRateRpc::returning(1)))
                    .is_ok(),
                "conf_target = {good} must build"
            );
            assert!(
                FeeSourceConfig::MempoolExplorer {
                    base_url: "https://mempool.space".parse().unwrap(),
                    policy: MempoolFeePolicy::Fastest,
                    fallback_conf_target: good,
                }
                .build(Arc::new(MockFeeRateRpc::returning(1)))
                .is_ok(),
                "fallback_conf_target = {good} must build"
            );
        }
    }

    #[test]
    fn fee_source_config_default_is_bitcoin_core_conf_target_1() {
        // Preserves pre-PR behaviour for operators upgrading without touching their config.
        let cfg = FeeSourceConfig::default();
        assert_eq!(cfg, FeeSourceConfig::BitcoinCore { conf_target: 1 });
    }
}
