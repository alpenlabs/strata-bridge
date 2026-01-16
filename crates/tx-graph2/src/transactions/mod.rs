//! This module contains the individual transactions of the Glock transaction graph.

use strata_bridge_connectors2::SigningInfo;

pub mod bridge_proof;
pub mod bridge_proof_timeout;
pub mod claim;
pub mod contest;
pub mod contested_payout;
pub mod cooperative_payout;
pub mod counterproof;
pub mod counterproof_ack;
pub mod deposit;
pub mod not_presigned;
pub mod prelude;
pub mod slash;
pub mod stake;
pub mod uncontested_payout;
pub mod withdrawal_fulfillment;

/// Bitcoin transaction that spends an N/N output.
///
/// `N_INPUTS` is the number of transaction inputs.
/// A presigned transaction has an N/N spending condition in each of its inputs.
pub trait PresignedTx<const N_INPUTS: usize> {
    /// Get the signing info for each transaction input.
    fn signing_info(&self) -> [SigningInfo; N_INPUTS];
}
