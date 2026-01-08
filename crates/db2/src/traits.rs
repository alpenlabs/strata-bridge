//! Standard persistence interfaces for a bridge node.

use std::fmt::Debug;

use bitcoin::Txid;
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::types::OperatorIdx;

/// Standard persistence interface for a bridge node.
pub trait BridgeDb {
    /// The error type returned by the database operations.
    type Error: Debug;

    /// Gets, if present, a Schnorr [`Signature`] from the database, given an [`OperatorIdx`], a
    /// [`Txid`] and an `input_index`.
    fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> impl Future<Output = Result<Option<Signature>, Self::Error>> + Send + Sync;

    /// Sets a Schnorr [`Signature`] from the database, given an [`OperatorIdx`], a [`Txid`] and an
    /// `input_index`.
    fn set_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + Sync;
}
