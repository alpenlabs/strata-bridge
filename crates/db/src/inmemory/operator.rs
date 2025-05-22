//! In-memory database traits and implementations for the operator.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use bitcoin::Txid;
use musig2::{AggNonce, PartialSignature, PubNonce};
use strata_bridge_primitives::{scripts::taproot::TaprootWitness, types::OperatorIdx};
use tokio::sync::RwLock;
use tracing::trace;

use crate::{errors::DbResult, operator::OperatorDb};

/// Maps a transaction input to a public nonce.
pub type TxInputToPubNonceMap = HashMap<(Txid, u32), PubNonce>;

/// Maps a transaction input to an aggregated nonce.
pub type TxInputToAggNonceMap = HashMap<(Txid, u32), AggNonce>;

/// Maps a transaction input to a partial signature.
pub type TxInputToPartialSignatureMap = HashMap<(Txid, u32), PartialSignature>;

/// Maps a transaction input to a taproot witness.
pub type TxInputToWitnessMap = HashMap<(Txid, u32), TaprootWitness>;

/// Maps an operator index to a transaction input to a public nonce.
pub type OperatorIdxToTxInputNonceMap = HashMap<OperatorIdx, TxInputToPubNonceMap>;

/// Maps an operator index to a transaction input to a partial signature.
pub type OperatorIdxToTxInputPartialSigMap = HashMap<OperatorIdx, TxInputToPartialSignatureMap>;

/// Maps an operator index to a transaction input to a taproot witness.
pub type OperatorIdxToTxInputWitnessMap = HashMap<OperatorIdx, TxInputToWitnessMap>;

/// In-memory database for the operator.    
#[derive(Debug, Default)]
pub struct OperatorDbInMemory {
    /// operator_id -> txid, input_index -> PubNonce
    pub_nonces: Arc<RwLock<OperatorIdxToTxInputNonceMap>>,

    /// operator_id -> txid, input_index -> AggNonce
    aggregated_nonces: Arc<RwLock<TxInputToAggNonceMap>>,

    /// operator_id -> txid, input_index -> PartialSignature (secp256k1::schnorr::Signature)
    partial_signatures: Arc<RwLock<OperatorIdxToTxInputPartialSigMap>>,

    /// operator_id -> txid, input_index -> TaprootWitness
    witnesses: Arc<RwLock<OperatorIdxToTxInputWitnessMap>>,
}

#[async_trait]
impl OperatorDb for OperatorDbInMemory {
    async fn get_pub_nonce(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<PubNonce>> {
        Ok(self
            .pub_nonces
            .read()
            .await
            .get(&operator_idx)
            .and_then(|m| m.get(&(txid, input_index)))
            .cloned())
    }

    async fn set_pub_nonce(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        pub_nonces: PubNonce, // Matched trait parameter name
    ) -> DbResult<()> {
        trace!(action = "trying to acquire wlock on pub_nonces", %operator_idx, %txid, input_index);
        let mut pub_nonces_map = self.pub_nonces.write().await;
        trace!(event = "acquired wlock on pub_nonces", %operator_idx, %txid, input_index);

        pub_nonces_map
            .entry(operator_idx)
            .or_default()
            .insert((txid, input_index), pub_nonces);

        Ok(())
    }

    async fn get_aggregated_nonce(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<AggNonce>> {
        Ok(self
            .aggregated_nonces
            .read()
            .await
            .get(&(txid, input_index))
            .cloned())
    }

    async fn set_aggregated_nonce(
        &self,
        txid: Txid,
        input_index: u32,
        pub_nonces: AggNonce, // Matched trait parameter name
    ) -> DbResult<()> {
        trace!(action = "trying to acquire wlock on aggregated_nonces", %txid, input_index);
        let mut aggregated_nonces_map = self.aggregated_nonces.write().await;
        trace!(event = "acquired wlock on aggregated_nonces", %txid, input_index);

        aggregated_nonces_map.insert((txid, input_index), pub_nonces);

        Ok(())
    }

    async fn get_partial_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<PartialSignature>> {
        Ok(self
            .partial_signatures
            .read()
            .await
            .get(&operator_idx)
            .and_then(|m| m.get(&(txid, input_index)))
            .copied())
    }

    async fn set_partial_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        partial_signature: PartialSignature,
    ) -> DbResult<()> {
        trace!(action = "trying to acquire wlock on partial_signatures", %operator_idx, %txid, input_index);
        let mut partial_signatures_map = self.partial_signatures.write().await;
        trace!(event = "acquired wlock on partial_signatures", %operator_idx, %txid, input_index);

        partial_signatures_map
            .entry(operator_idx)
            .or_default()
            .insert((txid, input_index), partial_signature);
        Ok(())
    }

    async fn get_witness(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<TaprootWitness>> {
        Ok(self
            .witnesses
            .read()
            .await
            .get(&operator_idx)
            .and_then(|m| m.get(&(txid, input_index)))
            .cloned())
    }

    async fn set_witness(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        witness: TaprootWitness,
    ) -> DbResult<()> {
        trace!(action = "trying to acquire wlock on witnesses", %operator_idx, %txid, input_index);
        let mut witnesses_map = self.witnesses.write().await;
        trace!(event = "acquired wlock on witnesses", %operator_idx, %txid, input_index);

        witnesses_map
            .entry(operator_idx)
            .or_default()
            .insert((txid, input_index), witness);
        Ok(())
    }
}
