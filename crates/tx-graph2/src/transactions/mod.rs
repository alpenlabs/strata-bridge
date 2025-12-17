//! This module contains the individual transactions of the Glock transaction graph.

use bitcoin::{OutPoint, TxOut};

pub mod claim;
pub mod prelude;

/// Bitcoin transaction that is the parent in a CPFP fee-bumping scheme.
pub trait ParentTx {
    /// Returns the output that is spent by the CPFP child.
    fn cpfp_tx_out(&self) -> TxOut;

    /// Returns the outpoint that is spent by the CPFP child.
    fn cpfp_outpoint(&self) -> OutPoint;
}
