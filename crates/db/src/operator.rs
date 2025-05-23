//! This module defines the OperatorDb trait, which is used to interact with the operator's
//! database.

use std::{
    collections::{BTreeMap, HashSet},
    sync::Arc,
};

use arbitrary::Arbitrary;
use async_trait::async_trait;
use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, TxOut, Txid};
use musig2::{AggNonce, PartialSignature, PubNonce, SecNonce};
use strata_bridge_primitives::{
    bitcoin::BitcoinAddress, scripts::taproot::TaprootWitness, types::OperatorIdx,
};
use tokio::sync::Mutex as TokioMutex;

use crate::errors::DbResult;

/// A map of message hash to operator ID to signature.
pub type MsgHashAndOpIdToSigMap = (Vec<u8>, BTreeMap<OperatorIdx, PartialSignature>);

/// The data required to create the Kickoff Transaction.
// NOTE: this type should ideally be part of the `tx-graph` crate but that leads to a cyclic
// dependency as the `tx-graph` crate also depends on this crate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KickoffInfo {
    /// The funding inputs for the kickoff transaction.
    pub funding_inputs: Vec<OutPoint>,

    /// The funding utxos for the kickoff transaction.
    pub funding_utxos: Vec<TxOut>,

    /// The change address for the kickoff transaction.
    pub change_address: BitcoinAddress,

    /// The change amount for the kickoff transaction.
    pub change_amt: Amount,
}

impl<'a> Arbitrary<'a> for KickoffInfo {
    fn arbitrary(u: &mut arbitrary::Unstructured<'a>) -> arbitrary::Result<Self> {
        let value = Amount::from_sat(u.int_in_range(0..=10_000_000_000)?);
        let txid = {
            let mut txid = [0; 32];
            u.fill_buffer(&mut txid)?;
            Txid::from_slice(&txid).map_err(|_| arbitrary::Error::IncorrectFormat)?
        };

        Ok(Self {
            funding_inputs: vec![OutPoint {
                txid,
                vout: u.arbitrary()?,
            }],
            funding_utxos: vec![TxOut {
                value,
                script_pubkey: ScriptBuf::new(),
            }],
            change_address: BitcoinAddress::arbitrary(u)?,
            change_amt: value
                .checked_div(10)
                .ok_or(arbitrary::Error::IncorrectFormat)?,
        })
    }
}

/// Interface to operate on the data required by the operator.
///
/// This data includes the public nonces, aggregated nonces and partial signatures required for the
/// operator to perform its duties. This interface operates on data that is either sensitive or not
/// required to be public.
#[async_trait]
pub trait OperatorDb {
    /// Gets, if present, a MuSig2 [`PubNonce`] from the database, given an [`OperatorIdx`],
    /// a [`Txid`], and an `input_index`.
    async fn get_pub_nonce(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<PubNonce>>;

    /// Sets a MuSig2 [`PubNonce`] in the database, for a given [`OperatorIdx`],
    /// a [`Txid`], and an `input_index`.
    async fn set_pub_nonce(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        pub_nonces: PubNonce,
    ) -> DbResult<()>;

    /// Gets, if present, a MuSig2 [`AggNonce`] (aggregated nonce) from the database,
    /// given a [`Txid`], and an `input_index`.
    async fn get_aggregated_nonce(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<AggNonce>>;

    /// Sets a MuSig2 [`AggNonce`] (aggregated nonce) in the database, for a given
    /// a [`Txid`], and an `input_index`.
    async fn set_aggregated_nonce(
        &self,
        txid: Txid,
        input_index: u32,
        pub_nonces: AggNonce,
    ) -> DbResult<()>;

    /// Gets, if present, a MuSig2 partial [`PartialSignature`] from the database,
    /// given an [`OperatorIdx`], a [`Txid`], and an `input_index`.
    async fn get_partial_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<PartialSignature>>;

    /// Sets a MuSig2 partial [`PartialSignature`] in the database, for a given [`OperatorIdx`],
    /// a [`Txid`], and an `input_index`.
    async fn set_partial_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: PartialSignature,
    ) -> DbResult<()>;

    /// Gets, if present, a MuSig2 [`TaprootWitness`] from the database,
    /// given an [`OperatorIdx`], a [`Txid`], and an `input_index`.
    async fn get_witness(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<TaprootWitness>>;

    /// Sets a MuSig2 [`TaprootWitness`] in the database, for a given [`OperatorIdx`],
    /// a [`Txid`], and an `input_index`.
    async fn set_witness(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        witness: TaprootWitness,
    ) -> DbResult<()>;
}

/// Legacy methods for backward compatibility with `agent` crate
///
/// This trait provides default implementations of the old OperatorDb interface
/// for any type that implements the new simplified OperatorDb trait.
#[deprecated(note = "Use `OperatorDb` instead")]
#[async_trait]
pub trait LegacyOperatorDbExt: OperatorDb {
    /// Legacy method: Add a public nonce for a specific operator
    #[deprecated(note = "Use set_pub_nonce instead")]
    async fn add_pubnonce(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        pubnonce: PubNonce,
    ) -> DbResult<()> {
        self.set_pub_nonce(operator_idx, txid, input_index, pubnonce)
            .await
    }

    /// Legacy method: Get collected public nonces for a transaction input
    #[deprecated(note = "Use get_pub_nonce for individual nonces")]
    async fn collected_pubnonces(
        &self,
        _txid: Txid,
        _input_index: u32,
    ) -> DbResult<Vec<(OperatorIdx, PubNonce)>> {
        // Return empty - this is a stub implementation
        Ok(Vec::new())
    }

    /// Legacy method: Add a secret nonce
    #[deprecated(note = "Secret nonces are no longer stored in the database")]
    async fn add_secnonce(
        &self,
        _txid: Txid,
        _input_index: u32,
        _secnonce: SecNonce,
    ) -> DbResult<()> {
        // No-op - this is a stub implementation
        Ok(())
    }

    /// Legacy method: Get a secret nonce
    #[deprecated(note = "Secret nonces are no longer stored in the database")]
    async fn get_secnonce(&self, _txid: Txid, _input_index: u32) -> DbResult<Option<SecNonce>> {
        // Return None - this is a stub implementation
        Ok(None)
    }

    /// Legacy method: Add a message hash and signature
    #[deprecated(note = "Use set_partial_signature instead")]
    async fn add_message_hash_and_signature(
        &self,
        _txid: Txid,
        _input_index: u32,
        _message_hash: Vec<u8>,
        _operator_idx: OperatorIdx,
        _signature: PartialSignature,
    ) -> DbResult<()> {
        // No-op - this is a stub implementation
        Ok(())
    }

    /// Legacy method: Get collected signatures per message
    #[deprecated(note = "Use get_partial_signature for individual signatures")]
    async fn collected_signatures_per_msg(
        &self,
        _txid: Txid,
        _input_index: u32,
    ) -> DbResult<Option<MsgHashAndOpIdToSigMap>> {
        // Return None - this is a stub implementation
        Ok(None)
    }

    /// Legacy method: Add a partial signature
    #[deprecated(note = "Use set_partial_signature instead")]
    async fn add_partial_signature(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) -> DbResult<()> {
        self.set_partial_signature(operator_idx, txid, input_index, signature)
            .await
    }

    /// Legacy method: Add an outpoint
    #[deprecated(note = "Outpoint management is no longer part of OperatorDb")]
    async fn add_outpoint(
        &self,
        _outpoint: OutPoint,
        _txout: TxOut,
        _address: BitcoinAddress,
    ) -> DbResult<()> {
        // No-op - this is a stub implementation
        Ok(())
    }

    /// Legacy method: Get selected outpoints
    #[deprecated(note = "Outpoint management is no longer part of OperatorDb")]
    async fn selected_outpoints(&self) -> DbResult<HashSet<OutPoint>> {
        // Return empty set - this is a stub implementation
        Ok(HashSet::new())
    }

    /// Legacy method: Add kickoff info
    #[deprecated(note = "Kickoff info management is no longer part of OperatorDb")]
    async fn add_kickoff_info(&self, _info: KickoffInfo) -> DbResult<()> {
        // No-op - this is a stub implementation
        Ok(())
    }

    /// Legacy method: Get kickoff info
    #[deprecated(note = "Kickoff info management is no longer part of OperatorDb")]
    async fn get_kickoff_info(&self, _txid: Txid) -> DbResult<Option<KickoffInfo>> {
        // Return None - this is a stub implementation
        Ok(None)
    }

    /// Legacy method: Get checkpoint index
    #[deprecated(note = "Checkpoint management is no longer part of OperatorDb")]
    async fn get_checkpoint_index(&self, _txid: Txid) -> DbResult<Option<u64>> {
        // Return None - this is a stub implementation
        Ok(None)
    }

    /// Legacy method: Set checkpoint index
    #[deprecated(note = "Checkpoint management is no longer part of OperatorDb")]
    async fn set_checkpoint_index(&self, _txid: Txid, _index: u64) -> DbResult<()> {
        // No-op - this is a stub implementation
        Ok(())
    }
}

// Automatically implement the extension trait for any OperatorDb implementation
#[expect(deprecated)]
impl<T: OperatorDb> LegacyOperatorDbExt for T {}

/// Legacy wrapper for backward compatibility with agent crate
///
/// This wrapper provides the old OperatorDb interface by implementing all legacy methods.
/// It wraps any type that implements the new OperatorDb trait and provides backward
/// compatibility for code that still uses the old interface.
#[derive(Debug, Clone)]
#[deprecated(note = "Use `OperatorDb` instead")]
pub struct LegacyOperatorDb<T> {
    inner: T,
    // In-memory storage for legacy functionality that's no longer in the database
    #[expect(clippy::type_complexity)]
    nonces: Arc<TokioMutex<BTreeMap<(Txid, u32), BTreeMap<OperatorIdx, PubNonce>>>>,
    secnonces: Arc<TokioMutex<BTreeMap<(Txid, u32), SecNonce>>>,
    signatures: Arc<TokioMutex<BTreeMap<(Txid, u32), MsgHashAndOpIdToSigMap>>>,
    outpoints: Arc<TokioMutex<HashSet<OutPoint>>>,
    kickoff_info: Arc<TokioMutex<BTreeMap<Txid, KickoffInfo>>>,
    checkpoint_indices: Arc<TokioMutex<BTreeMap<Txid, u64>>>,
}

#[expect(deprecated)]
impl<T> LegacyOperatorDb<T> {
    /// Create a new LegacyOperatorDb wrapper
    #[deprecated(note = "Use `OperatorDb` instead")]
    pub fn new(inner: T) -> Self {
        Self {
            inner,
            nonces: Arc::new(TokioMutex::new(BTreeMap::new())),
            secnonces: Arc::new(TokioMutex::new(BTreeMap::new())),
            signatures: Arc::new(TokioMutex::new(BTreeMap::new())),
            outpoints: Arc::new(TokioMutex::new(HashSet::new())),
            kickoff_info: Arc::new(TokioMutex::new(BTreeMap::new())),
            checkpoint_indices: Arc::new(TokioMutex::new(BTreeMap::new())),
        }
    }
}

#[async_trait]
#[expect(deprecated)]
impl<T: OperatorDb + Send + Sync> OperatorDb for LegacyOperatorDb<T> {
    async fn get_pub_nonce(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<PubNonce>> {
        self.inner
            .get_pub_nonce(operator_idx, txid, input_index)
            .await
    }

    async fn set_pub_nonce(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        pub_nonce: PubNonce,
    ) -> DbResult<()> {
        self.inner
            .set_pub_nonce(operator_idx, txid, input_index, pub_nonce)
            .await
    }

    async fn get_aggregated_nonce(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<AggNonce>> {
        self.inner.get_aggregated_nonce(txid, input_index).await
    }

    async fn set_aggregated_nonce(
        &self,
        txid: Txid,
        input_index: u32,
        agg_nonce: AggNonce,
    ) -> DbResult<()> {
        self.inner
            .set_aggregated_nonce(txid, input_index, agg_nonce)
            .await
    }

    async fn get_partial_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<PartialSignature>> {
        self.inner
            .get_partial_signature(operator_idx, txid, input_index)
            .await
    }

    async fn set_partial_signature(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        signature: PartialSignature,
    ) -> DbResult<()> {
        self.inner
            .set_partial_signature(operator_idx, txid, input_index, signature)
            .await
    }

    async fn get_witness(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<TaprootWitness>> {
        self.inner
            .get_witness(operator_idx, txid, input_index)
            .await
    }

    async fn set_witness(
        &self,
        operator_idx: OperatorIdx,
        txid: Txid,
        input_index: u32,
        witness: TaprootWitness,
    ) -> DbResult<()> {
        self.inner
            .set_witness(operator_idx, txid, input_index, witness)
            .await
    }
}

/// Legacy methods implementation for LegacyOperatorDb
#[expect(deprecated)]
impl<T: OperatorDb + Send + Sync> LegacyOperatorDb<T> {
    /// Legacy method: Add a public nonce for a specific operator
    #[deprecated(note = "Use set_pub_nonce instead")]
    pub async fn add_pubnonce(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        pubnonce: PubNonce,
    ) -> DbResult<()> {
        // Store in both the new interface and legacy map for compatibility
        self.set_pub_nonce(operator_idx, txid, input_index, pubnonce.clone())
            .await?;

        let mut nonces = self.nonces.lock().await;
        nonces
            .entry((txid, input_index))
            .or_insert_with(BTreeMap::new)
            .insert(operator_idx, pubnonce);
        Ok(())
    }

    /// Legacy method: Get collected public nonces for a transaction input
    #[deprecated(note = "Use get_pub_nonce for individual nonces")]
    pub async fn collected_pubnonces(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<BTreeMap<OperatorIdx, PubNonce>> {
        let nonces = self.nonces.lock().await;
        Ok(nonces
            .get(&(txid, input_index))
            .cloned()
            .unwrap_or_default())
    }

    /// Legacy method: Add a secret nonce
    #[deprecated(note = "Secret nonces are no longer stored in the database")]
    pub async fn add_secnonce(
        &self,
        txid: Txid,
        input_index: u32,
        secnonce: SecNonce,
    ) -> DbResult<()> {
        let mut secnonces = self.secnonces.lock().await;
        secnonces.insert((txid, input_index), secnonce);
        Ok(())
    }

    /// Legacy method: Get a secret nonce
    #[deprecated(note = "Secret nonces are no longer stored in the database")]
    pub async fn get_secnonce(&self, txid: Txid, input_index: u32) -> DbResult<Option<SecNonce>> {
        let secnonces = self.secnonces.lock().await;
        Ok(secnonces.get(&(txid, input_index)).cloned())
    }

    /// Legacy method: Add a message hash and signature
    #[deprecated(note = "Use set_partial_signature instead")]
    pub async fn add_message_hash_and_signature(
        &self,
        txid: Txid,
        input_index: u32,
        message_hash: Vec<u8>,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) -> DbResult<()> {
        let mut signatures = self.signatures.lock().await;
        let entry = signatures
            .entry((txid, input_index))
            .or_insert_with(|| (message_hash.clone(), BTreeMap::new()));
        entry.1.insert(operator_idx, signature);
        Ok(())
    }

    /// Legacy method: Get collected signatures per message
    #[deprecated(note = "Use get_partial_signature for individual signatures")]
    pub async fn collected_signatures_per_msg(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<MsgHashAndOpIdToSigMap>> {
        let signatures = self.signatures.lock().await;
        Ok(signatures.get(&(txid, input_index)).cloned())
    }

    /// Legacy method: Add a partial signature
    #[deprecated(note = "Use set_partial_signature instead")]
    pub async fn add_partial_signature(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) -> DbResult<()> {
        self.set_partial_signature(operator_idx, txid, input_index, signature)
            .await
    }

    /// Legacy method: Add an outpoint
    #[deprecated(note = "Outpoint management is no longer part of OperatorDb")]
    pub async fn add_outpoint(
        &self,
        outpoint: OutPoint,
        _txout: TxOut,
        _address: BitcoinAddress,
    ) -> DbResult<()> {
        let mut outpoints = self.outpoints.lock().await;
        outpoints.insert(outpoint);
        Ok(())
    }

    /// Legacy method: Get selected outpoints
    #[deprecated(note = "Outpoint management is no longer part of OperatorDb")]
    pub async fn selected_outpoints(&self) -> DbResult<HashSet<OutPoint>> {
        let outpoints = self.outpoints.lock().await;
        Ok(outpoints.clone())
    }

    /// Legacy method: Add kickoff info
    #[deprecated(note = "Kickoff info management is no longer part of OperatorDb")]
    pub async fn add_kickoff_info(&self, info: KickoffInfo) -> DbResult<()> {
        // Use a placeholder txid since the agent might not provide one
        let txid = Txid::from_slice(&[0; 32]).unwrap();
        let mut kickoff_info = self.kickoff_info.lock().await;
        kickoff_info.insert(txid, info);
        Ok(())
    }

    /// Legacy method: Get kickoff info
    #[deprecated(note = "Kickoff info management is no longer part of OperatorDb")]
    pub async fn get_kickoff_info(&self, txid: Txid) -> DbResult<Option<KickoffInfo>> {
        let kickoff_info = self.kickoff_info.lock().await;
        Ok(kickoff_info.get(&txid).cloned())
    }

    /// Legacy method: Get checkpoint index
    #[deprecated(note = "Checkpoint management is no longer part of OperatorDb")]
    pub async fn get_checkpoint_index(&self, txid: Txid) -> DbResult<Option<u64>> {
        let checkpoint_indices = self.checkpoint_indices.lock().await;
        Ok(checkpoint_indices.get(&txid).cloned())
    }

    /// Legacy method: Set checkpoint index
    #[deprecated(note = "Checkpoint management is no longer part of OperatorDb")]
    pub async fn set_checkpoint_index(&self, txid: Txid, index: u64) -> DbResult<()> {
        let mut checkpoint_indices = self.checkpoint_indices.lock().await;
        checkpoint_indices.insert(txid, index);
        Ok(())
    }
}
