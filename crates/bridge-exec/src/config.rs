//! Static configuration common to all duty executors.

use std::sync::Arc;

use bitcoin::{Amount, FeeRate, Network, XOnlyPublicKey};
use btc_tracker::cpfp::CachedFeeSource;
use strata_bridge_sm::graph::config::GraphSMCfg;
use strata_l1_txfmt::MagicBytes;

/// The static configuration for the duty executors.
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    /// The Bitcoin network to operate on.
    pub network: Network,

    /// The number of blocks before the withdrawal fulfillment deadline after which the operator
    /// will not attempt to perform a fulfillment. This is a safety mechanism.
    pub min_withdrawal_fulfillment_window: u64,

    /// Magic bytes for bridge identification in SPS-50 headers.
    pub magic_bytes: MagicBytes,

    /// Maximum fee rate for broadcasting transactions. If the estimated fee rate exceeds this,
    /// the transaction will not be broadcast.
    pub maximum_fee_rate: FeeRate,

    /// The fee charged by an operator for processing a withdrawal.
    pub operator_fee: Amount,

    /// The amount of BTC this operator stakes as collateral. The stake-funding UTXO spent by the
    /// stake transaction must carry `stake_amount` plus any connector dust the stake tx produces.
    pub stake_amount: Amount,

    /// The target number of claim-funding UTXOs to keep available in the reserved wallet.
    /// When the pool is exhausted, the duty dispatcher tops it back up to this size.
    pub funding_uxto_pool_size: usize,

    /// musig2 keys of every operator that contests claims, excluding the operator running this
    /// node. Drives the per-UTXO denomination of the claim-funding pool via
    /// [`crate::claim_funding::utxo_value`]; the connector that the claim tx must pay for scales
    /// with the watchtower count.
    ///
    /// Today this is snapshotted from `params.keys.covenant` at orchestrator startup, since the
    /// operator set doesn't change at runtime yet. The value lives here (rather than as a
    /// precomputed `claim_funding_utxo_value: Amount`) so the executors recompute the
    /// denomination on every duty firing — when runtime operator entry/exit lands, only the
    /// source of this field needs to swap to a live handle and the executors get correct values
    /// without further plumbing.
    pub watchtower_musig2_keys: Arc<Vec<XOnlyPublicKey>>,

    /// The graph state-machine configuration, shared with the GSM to keep protocol parameters
    /// and static keys consistent across graph construction paths.
    pub graph_sm_cfg: Arc<GraphSMCfg>,

    /// Background-refreshed fee-rate cache shared with the tx-driver's CPFP bump loop. Executors
    /// read the current cached rate via [`CachedFeeSource::current`] per tx-build (no network I/O
    /// on the hot path); the cache is refreshed by a background task at the configured interval.
    pub fee_source: Arc<CachedFeeSource>,
}
