//! Static configuration common to all duty executors.

use std::sync::Arc;

use bitcoin::{Amount, Network};
use strata_bridge_sm::graph::config::GraphSMCfg;
use strata_l1_txfmt::MagicBytes;

use crate::fees::{FeeQuoteMemo, FeeTargetPolicy};

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

    /// Fee target policy: the premium, the floor and the maximum fee rate. No transaction pays
    /// more than [`FeeTargetPolicy::max_fee_rate`]. The CPFP ladder applies the same policy.
    pub fee_target: FeeTargetPolicy,

    /// The fee charged by an operator for processing a withdrawal.
    pub operator_fee: Amount,

    /// The amount of BTC this operator stakes as collateral. The stake-funding UTXO spent by the
    /// stake transaction must carry `stake_amount` plus any connector dust the stake tx produces.
    pub stake_amount: Amount,

    /// The target number of claim-funding UTXOs to keep available in the reserved wallet for
    /// each claim-funding amount. When the pool of a graph's amount is exhausted, the duty
    /// dispatcher tops it back up to this size.
    pub funding_uxto_pool_size: usize,

    /// The number of blocks built on top of a transaction's block before it counts as
    /// [`TxStatus::Buried`](btc_tracker::event::TxStatus).
    pub bury_depth: u32,

    /// The graph state-machine configuration, shared with the GSM to keep protocol parameters
    /// and static keys consistent across graph construction paths.
    pub graph_sm_cfg: Arc<GraphSMCfg>,

    /// Fee quote memo shared with the tx-driver's CPFP bump loop. Executors read it through
    /// [`FeeQuoteMemo::duty_rates`] per tx-build. A frozen quote fails the duty, which retries
    /// after the source recovers.
    pub fee_source: Arc<FeeQuoteMemo>,
}
