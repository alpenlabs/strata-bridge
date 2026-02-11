//! Static configuration common to all duty executors.

use bitcoin::Network;
use strata_bridge_primitives::operator_table::OperatorTable;
use strata_l1_txfmt::MagicBytes;

/// The static configuration for the duty executors.
#[derive(Debug, Clone)]
pub struct ExecutionConfig {
    /// The Bitcoin network to operate on.
    pub network: Network,

    /// The minimum number of blocks required between the current block height and the withdrawal
    /// fulfillment deadline in order to perform a fulfillment.
    pub min_withdrawal_fulfillment_window: u64,

    /// The operator table containing all operator public keys for MuSig2 signing.
    pub operator_table: OperatorTable,

    /// Magic bytes for bridge identification in SPS-50 headers.
    pub magic_bytes: MagicBytes,
}
