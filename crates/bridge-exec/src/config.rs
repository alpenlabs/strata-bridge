//! Static configuration common to all duty executors.

use std::sync::Arc;

use bitcoin::{Amount, FeeRate, Network};
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

    /// The number of claim funding utxos to generate at any given time when the pool is exhausted.
    pub funding_uxto_pool_size: usize,

    /// The graph state-machine configuration, shared with the GSM to keep protocol parameters
    /// and static keys consistent across graph construction paths.
    pub graph_sm_cfg: Arc<GraphSMCfg>,
}
