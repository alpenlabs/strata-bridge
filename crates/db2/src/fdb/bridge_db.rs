//! Implementation of the [`BridgeDb`] trait for FdbClient.

use std::fmt::Debug;

use bitcoin::Txid;
use foundationdb::{FdbBindingError, RetryableTransaction};
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::types::OperatorIdx;
use terrors::OneOf;

use crate::{fdb::FdbClient, traits::BridgeDb};

/// Standard error type for FoundationDB layer errors
#[derive(Debug)]
pub enum LayerError {
    /// The KV row was corrupted or invalid. No programmatic information is
    /// available, but the error is loggable.
    CorruptedEntry(Box<dyn Debug>),
}

impl BridgeDb for FdbClient {
    type Error = OneOf<(FdbBindingError, LayerError)>;

    async fn get_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> Result<Option<Signature>, Self::Error> {
        let trx = |trx: RetryableTransaction, _maybe_committed| {
            let key = self.dirs.signatures.key(operator_idx, txid, input_index);
            async move { Ok(trx.get(&key, true).await?) }
        };
        let Some(sig_bytes) = self.db.run(trx).await.map_err(OneOf::new)? else {
            return Ok(None);
        };
        let sig = Signature::from_slice(&sig_bytes)
            .map_err(|e| LayerError::CorruptedEntry(Box::new(e)))
            .map_err(OneOf::new)?;
        Ok(Some(sig))
    }

    async fn set_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: Signature,
    ) -> Result<(), Self::Error> {
        let trx = |trx: RetryableTransaction, _maybe_committed| async move {
            let key = self.dirs.signatures.key(operator_idx, txid, input_index);
            trx.set(&key, &signature.serialize());
            Ok(())
        };
        self.db.run(trx).await.map_err(OneOf::new)
    }
}
