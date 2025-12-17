//! This module contains the individual transactions of the Glock transaction graph.

use bitcoin::{OutPoint, TxOut};

use crate::connectors::SigningInfo;

pub mod bridge_proof;
pub mod claim;
pub mod contest;
pub mod deposit;
pub mod prelude;
pub mod uncontested_payout;

/// Bitcoin transaction that is the parent in a CPFP fee-bumping scheme.
pub trait ParentTx {
    /// Returns the output that is spent by the CPFP child.
    fn cpfp_tx_out(&self) -> TxOut;

    /// Returns the outpoint that is spent by the CPFP child.
    fn cpfp_outpoint(&self) -> OutPoint;
}

/// Bitcoin transaction that spends an N/N output.
///
/// `N_INPUTS` is the number of transaction inputs.
/// A presigned transaction has an N/N spending condition in each of its inputs.
pub trait PresignedTx<const N_INPUTS: usize> {
    /// Get the signing info for each transaction input.
    fn signing_info(&self) -> [SigningInfo; N_INPUTS];
}
