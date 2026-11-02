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
//! The orchestrator builds the configured source via [`FeeSourceConfig::build`] and wraps it in
//! a [`FeeQuoteMemo`], which the executors and the CPFP ladder share, so neither hits the network
//! per call and both keep a last known rate when the source fails.

use std::{fmt, sync::Arc, time::Duration};

use async_trait::async_trait;
use bitcoin::FeeRate;
use bitcoind_async_client::{ClientResult, traits::Reader};
use serde::{Deserialize, Serialize};
use strata_bridge_tx_graph::fee;
use thiserror::Error;
use tokio::{
    sync::Mutex,
    time::{Instant, timeout},
};
use tracing::warn;
use url::Url;

use crate::errors::ExecutorError;

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
///
/// In production the configured source sits behind a [`FeeQuoteMemo`], so the ladder and the
/// executors share one quote and do not hit the network per call.
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
/// economical estimate; see [`TargetRates::next_block`]. On a public network with a varied mempool
/// the `MempoolExplorerFeeSource` follows a rising backlog sooner.
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
/// Intended for tests and emergency manual overrides. The source itself clamps nothing. The floors
/// of the wallet-funded paths and the ladder still apply to its rate.
#[derive(Debug)]
struct FixedFeeSource(FeeRate);

#[async_trait]
impl FeeSource for FixedFeeSource {
    async fn next_block_rate(&self) -> Result<FeeRate, FeeSourceError> {
        Ok(self.0)
    }
}

/// How long a quote answers reads with no upstream call. The default bump interval must stay above
/// this, so that each bump tick of an idle node reads a new quote. A failed upstream read waits the
/// same time before the next attempt, measured from its end, so a down source costs one slow
/// failure per period and not one per caller.
pub const QUOTE_TTL: Duration = Duration::from_secs(25);

/// Oldest quote that [`FeeQuoteMemo::duty_rate`] accepts, at the moment of the read. The duty then
/// waits for the wallet guard and a sync before it funds, so the rate it pays can be older than
/// this by that wait. Nothing reads between callers, so a quote can reach this age on an idle node
/// with no failed read. In that case one failed read refuses the duty.
const MAX_QUOTE_AGE: Duration = Duration::from_secs(300);

/// Upper bound on one upstream read. Callers wait for the read, and one of them can be a bump
/// with a deadline. This covers the 10 s explorer timeout and 10 s of Core time. It is shorter than
/// the Core client's own 30 s timeout, so a slow Core answer is lost and the last quote stands.
/// A read past the bound counts as a failed read.
const QUOTE_READ_TIMEOUT: Duration = Duration::from_secs(20);

/// The last rate that the memo holds.
#[derive(Debug, Clone, Copy)]
struct Quote {
    rate: FeeRate,
    fetched_at: Instant,
}

#[derive(Debug)]
struct MemoState {
    /// The last quote. `None` until the first read that returns a rate or a missing estimate.
    quote: Option<Quote>,
    /// The end of the last upstream attempt. `None` before the first.
    attempted_at: Option<Instant>,
}

/// Read-through memo over the configured [`FeeSource`], shared by the executors and the CPFP
/// ladder.
///
/// A read inside `QUOTE_TTL` of the end of the last upstream attempt does no I/O. A later read goes
/// upstream on the caller's task, and concurrent callers wait for that one read. Nothing runs
/// between reads, so an idle node makes no fee requests.
///
/// A failed upstream read keeps the last quote, and the two kinds of caller then differ:
///
/// - A bump reads through [`FeeSource::next_block_rate`], which always returns the last quote. A
///   bump at an old rate is better than no bump, because the parent otherwise pays only its own
///   fee.
/// - A wallet-funded duty reads through [`Self::duty_rate`], which refuses a quote older than
///   `MAX_QUOTE_AGE`. A frozen quote prices a transaction at the market from before the source
///   failed. The error fails the duty, which waits for the next `retry_interval` tick.
///
/// A source with no estimate ([`FeeSourceError::NoEstimate`]) gives a quote at the floor rate, as
/// on a node that reads `estimatesmartfee` directly. A warning fires on each such read.
#[derive(Debug)]
pub struct FeeQuoteMemo {
    source: Arc<dyn FeeSource>,
    /// Held across the upstream read, which makes that read single-flight.
    state: Mutex<MemoState>,
}

impl FeeQuoteMemo {
    /// A memo over `source` with no quote yet. The first read of a rate asks the source, so a
    /// source that is down at construction stops nothing at startup.
    pub fn new(source: Arc<dyn FeeSource>) -> Self {
        Self {
            source,
            state: Mutex::new(MemoState {
                quote: None,
                attempted_at: None,
            }),
        }
    }

    /// Returns the last quote, after one upstream read if the TTL has passed. `None` while no
    /// read has answered: a bump then prices at the floor, and a duty refuses.
    async fn quote(&self) -> Option<Quote> {
        let mut state = self.state.lock().await;
        let ttl_passed = state
            .attempted_at
            .is_none_or(|attempted_at| attempted_at.elapsed() >= QUOTE_TTL);
        if ttl_passed {
            let result = timeout(QUOTE_READ_TIMEOUT, self.source.next_block_rate()).await;
            let now = Instant::now();
            state.attempted_at = Some(now);
            let quote_age_secs = state
                .quote
                .map(|quote| quote.fetched_at.elapsed().as_secs());
            match result {
                Ok(Ok(rate)) => {
                    state.quote = Some(Quote {
                        rate,
                        fetched_at: now,
                    });
                }
                Ok(Err(error @ FeeSourceError::NoEstimate)) => {
                    // Without this log a cold node is indistinguishable from a calm mempool, and
                    // every bump quietly targets the minimum.
                    warn!(%error, "fee source has no estimate; the floor fee rate stands in");
                    state.quote = Some(Quote {
                        rate: MIN_SOURCE_FEE_RATE,
                        fetched_at: now,
                    });
                }
                Ok(Err(error)) => warn!(
                    %error,
                    ?quote_age_secs, "fee source read failed; the last quote stays in use"
                ),
                Err(_) => warn!(
                    timeout_secs = QUOTE_READ_TIMEOUT.as_secs(),
                    ?quote_age_secs,
                    "fee source read timed out; the last quote stays in use"
                ),
            }
        }
        state.quote
    }

    /// Returns the rate for a wallet-funded duty. Refuses a quote older than `MAX_QUOTE_AGE`, and
    /// refuses while no read has answered: a value that no source produced must not price a
    /// transaction. A source with no estimate gives the floor.
    pub async fn duty_rate(&self) -> Result<FeeRate, NoDutyFeeRate> {
        let quote = self.quote().await.ok_or(NoDutyFeeRate::NoQuote)?;
        let age = quote.fetched_at.elapsed();
        if age > MAX_QUOTE_AGE {
            return Err(NoDutyFeeRate::QuoteTooOld { age });
        }
        Ok(quote.rate)
    }
}

#[async_trait]
impl FeeSource for FeeQuoteMemo {
    /// Never returns `Err`: the last quote answers when the upstream read fails, and the floor
    /// answers while no read has.
    async fn next_block_rate(&self) -> Result<FeeRate, FeeSourceError> {
        Ok(self
            .quote()
            .await
            .map_or(MIN_SOURCE_FEE_RATE, |quote| quote.rate))
    }
}

/// The memo holds no quote that can price a wallet-funded duty.
#[derive(Debug, PartialEq, Eq, Error)]
pub enum NoDutyFeeRate {
    /// No upstream read has answered yet.
    #[error("no fee quote yet: the fee source has not answered")]
    NoQuote,
    /// The quote is older than `MAX_QUOTE_AGE`.
    #[error("fee quote is stale: {}s old, past the {}s bound", .age.as_secs(), MAX_QUOTE_AGE.as_secs())]
    QuoteTooOld {
        /// Time since the last successful read.
        age: Duration,
    },
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
/// they clamp up. The memo uses it as the rate of a source with no estimate.
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

/// Operator policy that turns a next-block estimate into the fee rate a package must reach.
///
/// Only the CPFP ladder reads this. A transaction that a duty funds pays the raw next-block
/// estimate, floored at [`fee::FEE_RATE`] (the burn: at [`FeeRate::BROADCAST_MIN`]), and its first
/// bump waits for a trigger, so the premium applies only to a parent that stays unconfirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FeeTargetPolicy {
    /// Percentage added to the next-block estimate, rounded up in sat/kwu. A value of `0` keeps
    /// the raw estimate.
    pub premium_percent: u32,
    /// Lower bound of the target, applied after the premium.
    pub min_package_fee_rate: FeeRate,
    /// Upper bound of the target. It wins over the premium and over the lower bound.
    pub max_fee_rate: FeeRate,
}

impl FeeTargetPolicy {
    /// Returns the rate that `next_block` asks for: the premium, then the lower bound, with no cap.
    /// The premium rounds up, so it never lowers the rate. A raised rate that does not fit a
    /// [`FeeRate`] saturates, so it reaches the cap and not a low value.
    pub(crate) fn wanted(&self, next_block: FeeRate) -> FeeRate {
        let rate_kwu = u128::from(next_block.to_sat_per_kwu());
        let multiplier = u128::from(self.premium_percent) + 100;
        let raised = rate_kwu.saturating_mul(multiplier).div_ceil(100);
        FeeRate::from_sat_per_kwu(raised.try_into().unwrap_or(u64::MAX))
            .max(self.min_package_fee_rate)
    }

    /// Returns the fee rate target for `next_block`.
    ///
    /// A clamp to [`Self::max_fee_rate`] logs at warn: the operator pays no more than the cap,
    /// and the transaction can stay behind the market.
    pub fn target(&self, next_block: FeeRate) -> FeeRate {
        let estimated = self.wanted(next_block);
        if estimated > self.max_fee_rate {
            warn!(
                ?estimated,
                cap = ?self.max_fee_rate,
                "fee target exceeds max_fee_rate; clamping to the cap"
            );
            return self.max_fee_rate;
        }
        estimated
    }
}

/// Fee rate for a wallet-funded transaction that must confirm promptly: withdrawal fulfillment,
/// stake funding and the bridge proof. It reads the next-block rate of the shared memo, bounded
/// from below by `fee::FEE_RATE` so the v3 transaction always meets the bridge's hardcoded minimum
/// even on networks where `estimatesmartfee` returns a value below `minrelaytxfee`.
///
/// A rate above `max_fee_rate` fails with [`ExecutorError::FeeRateTooHigh`]. Publishing below the
/// market is not safe here: a fulfillment can settle after a reassignment, and the operator loses
/// the funds.
///
/// This can read upstream for up to [`QUOTE_READ_TIMEOUT`]. A caller that holds the wallet guard
/// across it stops every other wallet user for that time.
pub(crate) async fn direct_funding_fee_rate(
    fee_source: &FeeQuoteMemo,
    max_fee_rate: FeeRate,
) -> Result<FeeRate, ExecutorError> {
    let fee_rate = fee_source.duty_rate().await?.max(fee::FEE_RATE);
    refuse_above_cap(fee_rate, max_fee_rate)
}

/// Fee rate for the unstaking burn. It reads the next-block rate of the shared memo, floored at
/// [`FeeRate::BROADCAST_MIN`] so that the transaction stays relayable. The burn is the one
/// duty-funded transaction below the protocol floor of [`fee::FEE_RATE`]: it is not part of a
/// presigned graph, and main priced it this way. A rate above `max_fee_rate` fails with
/// [`ExecutorError::FeeRateTooHigh`], and the caller skips the burn.
///
/// This can read upstream for up to [`QUOTE_READ_TIMEOUT`]. A caller that holds the wallet guard
/// across it stops every other wallet user for that time.
pub(crate) async fn burn_fee_rate(
    fee_source: &FeeQuoteMemo,
    max_fee_rate: FeeRate,
) -> Result<FeeRate, ExecutorError> {
    let fee_rate = fee_source.duty_rate().await?.max(FeeRate::BROADCAST_MIN);
    refuse_above_cap(fee_rate, max_fee_rate)
}

fn refuse_above_cap(fee_rate: FeeRate, max_fee_rate: FeeRate) -> Result<FeeRate, ExecutorError> {
    if fee_rate > max_fee_rate {
        return Err(ExecutorError::FeeRateTooHigh {
            fee_rate,
            max: max_fee_rate,
        });
    }
    Ok(fee_rate)
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };

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

    fn sat_vb(rate: u64) -> FeeRate {
        FeeRate::from_sat_per_vb(rate).expect("valid rate")
    }

    fn policy(premium_percent: u32, floor: u64, cap: u64) -> FeeTargetPolicy {
        FeeTargetPolicy {
            premium_percent,
            min_package_fee_rate: sat_vb(floor),
            max_fee_rate: sat_vb(cap),
        }
    }

    #[test]
    fn fee_target_applies_premium_then_floor_then_cap() {
        assert_eq!(policy(50, 0, 100).target(sat_vb(10)), sat_vb(15));
        assert_eq!(policy(50, 20, 100).target(sat_vb(10)), sat_vb(20));
        assert_eq!(policy(50, 0, 12).target(sat_vb(10)), sat_vb(12));
        assert_eq!(
            policy(0, 200, 100).target(sat_vb(10)),
            sat_vb(100),
            "the cap wins over the floor"
        );
        assert_eq!(
            policy(u32::MAX, 0, 100).target(FeeRate::from_sat_per_kwu(u64::MAX)),
            sat_vb(100),
            "a raised rate that overflows reaches the cap"
        );
    }

    /// The premium rounds up in sat/kwu, so a fractional raise never prices below the market.
    #[test]
    fn fee_premium_rounds_up_in_sat_kwu() {
        // 750 sat/kwu (3 sat/vB) raised by 5% is 787.5 sat/kwu, which rounds to 788.
        assert_eq!(
            policy(5, 0, 1000).wanted(FeeRate::from_sat_per_kwu(750)),
            FeeRate::from_sat_per_kwu(788)
        );
    }

    #[tokio::test]
    async fn direct_funding_pays_the_next_block_rate_with_no_premium() {
        let memo = FeeQuoteMemo::new(ScriptedFeeSource::returning(20));

        assert_eq!(
            direct_funding_fee_rate(&memo, sat_vb(100))
                .await
                .expect("fresh quote"),
            sat_vb(20),
        );
    }

    #[tokio::test]
    async fn direct_funding_stays_relayable_and_refuses_above_the_cap() {
        let memo = |rate| FeeQuoteMemo::new(ScriptedFeeSource::returning(rate));
        assert_eq!(
            direct_funding_fee_rate(&memo(1), sat_vb(100))
                .await
                .expect("fresh quote"),
            fee::FEE_RATE
        );
        assert!(matches!(
            direct_funding_fee_rate(&memo(500), sat_vb(100)).await,
            Err(ExecutorError::FeeRateTooHigh { .. })
        ));
    }

    /// Fee source that counts reads and whose result can be swapped mid-test.
    #[derive(Debug)]
    struct ScriptedFeeSource {
        reads: AtomicUsize,
        result: std::sync::Mutex<Result<FeeRate, FeeSourceError>>,
    }

    impl ScriptedFeeSource {
        fn returning(sat_per_vb: u64) -> Arc<Self> {
            Arc::new(Self {
                reads: AtomicUsize::new(0),
                result: std::sync::Mutex::new(Ok(sat_vb(sat_per_vb))),
            })
        }

        fn set(&self, result: Result<FeeRate, FeeSourceError>) {
            *self.result.lock().unwrap() = result;
        }

        fn fail(&self) {
            self.set(Err(ClientError::Request("source died".into()).into()));
        }

        fn reads(&self) -> usize {
            self.reads.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl FeeSource for ScriptedFeeSource {
        async fn next_block_rate(&self) -> Result<FeeRate, FeeSourceError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            self.result.lock().unwrap().clone()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn memo_serves_reads_inside_the_ttl_with_no_upstream_read() {
        let source = ScriptedFeeSource::returning(12);
        let memo = FeeQuoteMemo::new(source.clone());
        assert_eq!(source.reads(), 0, "the constructor reads nothing");
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(12));
        assert_eq!(source.reads(), 1, "the first caller reads the first quote");

        source.set(Ok(sat_vb(20)));
        tokio::time::advance(QUOTE_TTL - Duration::from_secs(1)).await;
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(12));
        assert_eq!(memo.duty_rate().await.unwrap(), sat_vb(12));
        assert_eq!(source.reads(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn memo_reads_through_once_the_ttl_passes() {
        let source = ScriptedFeeSource::returning(12);
        let memo = FeeQuoteMemo::new(source.clone());
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(12));

        source.set(Ok(sat_vb(20)));
        tokio::time::advance(QUOTE_TTL).await;
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(20));
        assert_eq!(
            memo.duty_rate().await.unwrap(),
            sat_vb(20),
            "the second read shares the first one's upstream call"
        );
        assert_eq!(source.reads(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn memo_makes_no_upstream_read_between_callers() {
        let source = ScriptedFeeSource::returning(12);
        let _memo = FeeQuoteMemo::new(source.clone());

        tokio::time::advance(QUOTE_TTL * 10).await;
        tokio::task::yield_now().await;
        assert_eq!(source.reads(), 0, "nothing reads while nobody asks");
    }

    /// A source that is down at the first read serves the floor to bumps until it answers, and
    /// refuses duties: no source produced that value.
    #[tokio::test(start_paused = true)]
    async fn a_failed_first_read_serves_the_floor_to_bumps_and_refuses_duties() {
        let source = ScriptedFeeSource::returning(12);
        source.fail();
        let memo = FeeQuoteMemo::new(source.clone());
        assert_eq!(memo.next_block_rate().await.unwrap(), MIN_SOURCE_FEE_RATE);
        assert_eq!(memo.duty_rate().await, Err(NoDutyFeeRate::NoQuote));

        source.set(Ok(sat_vb(12)));
        tokio::time::advance(QUOTE_TTL).await;
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(12));
    }

    #[tokio::test(start_paused = true)]
    async fn a_failed_read_keeps_the_last_quote_and_waits_a_ttl_to_retry() {
        let source = ScriptedFeeSource::returning(12);
        let memo = FeeQuoteMemo::new(source.clone());
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(12));

        source.fail();
        tokio::time::advance(QUOTE_TTL).await;
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(12));
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(12));
        assert_eq!(source.reads(), 2, "a failed read holds off the next one");

        source.set(Ok(sat_vb(20)));
        tokio::time::advance(QUOTE_TTL).await;
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(20));
    }

    /// A wallet-funded duty refuses a quote past the bound, while a bump keeps the last rate.
    #[tokio::test(start_paused = true)]
    async fn a_frozen_quote_fails_duty_pricing_and_serves_bumps() {
        let source = ScriptedFeeSource::returning(12);
        let memo = FeeQuoteMemo::new(source.clone());
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(12));

        source.fail();
        tokio::time::advance(MAX_QUOTE_AGE).await;
        assert_eq!(
            memo.duty_rate().await.unwrap(),
            sat_vb(12),
            "a quote at the bound still prices a duty"
        );

        tokio::time::advance(Duration::from_secs(1)).await;
        let err = memo
            .duty_rate()
            .await
            .expect_err("a frozen quote must refuse duty pricing");
        assert!(matches!(err, NoDutyFeeRate::QuoteTooOld { age } if age > MAX_QUOTE_AGE));
        assert_eq!(
            memo.next_block_rate().await.unwrap(),
            sat_vb(12),
            "a bump keeps the last known rate"
        );
        assert!(matches!(
            direct_funding_fee_rate(&memo, sat_vb(100)).await,
            Err(ExecutorError::NoDutyFeeRate(_))
        ));

        source.set(Ok(sat_vb(20)));
        tokio::time::advance(QUOTE_TTL).await;
        assert_eq!(
            memo.duty_rate().await.unwrap(),
            sat_vb(20),
            "the duty prices again once the source recovers"
        );
    }

    /// A source with no estimate prices at the floor, on every network, as a node that reads
    /// `estimatesmartfee` directly would.
    #[tokio::test(start_paused = true)]
    async fn a_missing_estimate_prices_at_the_floor() {
        let source = ScriptedFeeSource::returning(50);
        let memo = FeeQuoteMemo::new(source.clone());
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(50));

        source.set(Err(FeeSourceError::NoEstimate));
        tokio::time::advance(QUOTE_TTL).await;
        assert_eq!(memo.next_block_rate().await.unwrap(), MIN_SOURCE_FEE_RATE);
        assert_eq!(memo.duty_rate().await, Ok(MIN_SOURCE_FEE_RATE));
    }

    /// Source that answers its first read and hangs on every later one.
    #[derive(Debug, Default)]
    struct HangingFeeSource {
        reads: AtomicUsize,
    }

    #[async_trait]
    impl FeeSource for HangingFeeSource {
        async fn next_block_rate(&self) -> Result<FeeRate, FeeSourceError> {
            if self.reads.fetch_add(1, Ordering::SeqCst) == 0 {
                return Ok(sat_vb(12));
            }
            std::future::pending().await
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_hung_read_times_out_and_the_ttl_runs_from_its_end() {
        let source = Arc::new(HangingFeeSource::default());
        let memo = FeeQuoteMemo::new(source.clone());
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(12));

        tokio::time::advance(QUOTE_TTL).await;
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(12));
        assert_eq!(source.reads.load(Ordering::SeqCst), 2);

        tokio::time::advance(QUOTE_TTL - Duration::from_secs(1)).await;
        assert_eq!(memo.next_block_rate().await.unwrap(), sat_vb(12));
        assert_eq!(
            source.reads.load(Ordering::SeqCst),
            2,
            "a read inside the TTL after the timeout makes no upstream call"
        );
    }

    /// Source whose read takes time, so that callers overlap.
    #[derive(Debug, Default)]
    struct SlowFeeSource {
        reads: AtomicUsize,
    }

    #[async_trait]
    impl FeeSource for SlowFeeSource {
        async fn next_block_rate(&self) -> Result<FeeRate, FeeSourceError> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(1)).await;
            Ok(sat_vb(12))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn overlapping_reads_share_one_upstream_read() {
        let source = Arc::new(SlowFeeSource::default());
        let memo = FeeQuoteMemo::new(source.clone());

        tokio::time::advance(QUOTE_TTL).await;
        let (first, second) = tokio::join!(memo.next_block_rate(), memo.next_block_rate());
        assert_eq!(first.unwrap(), second.unwrap());
        assert_eq!(source.reads.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn burn_rate_applies_the_relay_floor_and_refuses_above_the_cap() {
        let memo = |rate| FeeQuoteMemo::new(ScriptedFeeSource::returning(rate));
        let cap = FeeRate::from_sat_per_vb(5).unwrap();
        assert_eq!(
            burn_fee_rate(&memo(0), cap).await.unwrap(),
            FeeRate::BROADCAST_MIN
        );
        assert_eq!(
            burn_fee_rate(&memo(5), cap).await.unwrap(),
            cap,
            "a rate at the cap passes"
        );
        assert!(matches!(
            burn_fee_rate(&memo(6), cap).await,
            Err(ExecutorError::FeeRateTooHigh { .. })
        ));
    }
}
