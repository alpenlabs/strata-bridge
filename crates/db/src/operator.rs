//! This module defines the OperatorDb trait, which is used to interact with the operator's
//! database.

use std::collections::{BTreeMap, HashSet};

use arbitrary::Arbitrary;
use async_trait::async_trait;
use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, TxOut, Txid};
use musig2::{PartialSignature, PubNonce, SecNonce};
use strata_bridge_primitives::{bitcoin::BitcoinAddress, types::OperatorIdx};

use crate::errors::DbResult;

pub type MsgHashAndOpIdToSigMap = (Vec<u8>, BTreeMap<OperatorIdx, PartialSignature>);

/// The data required to create the Kickoff Transaction.
// NOTE: this type should ideally be part of the `tx-graph` crate but that leads to a cyclic
// dependency as the `tx-graph` crate also depends on this crate.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct KickoffInfo {
    pub funding_inputs: Vec<OutPoint>,
    pub funding_utxos: Vec<TxOut>,
    pub change_address: BitcoinAddress,
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
/// This data includes the pubnonces, secnonces, and signatures required for the operator to perform
/// its duties. This interface operates on data that is either sensitive or not required to be
/// public.
#[async_trait]
pub trait OperatorDb {
    async fn add_pubnonce(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        pubnonce: PubNonce,
    ) -> DbResult<()>;

    async fn collected_pubnonces(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<BTreeMap<OperatorIdx, PubNonce>>;

    async fn add_secnonce(&self, txid: Txid, input_index: u32, secnonce: SecNonce) -> DbResult<()>;

    async fn get_secnonce(&self, txid: Txid, input_index: u32) -> DbResult<Option<SecNonce>>;

    async fn add_message_hash_and_signature(
        &self,
        txid: Txid,
        input_index: u32,
        message_sighash: Vec<u8>,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) -> DbResult<()>;

    /// Adds a partial signature to the map if already present.
    async fn add_partial_signature(
        &self,
        txid: Txid,
        input_index: u32,
        operator_idx: OperatorIdx,
        signature: PartialSignature,
    ) -> DbResult<()>;

    async fn collected_signatures_per_msg(
        &self,
        txid: Txid,
        input_index: u32,
    ) -> DbResult<Option<MsgHashAndOpIdToSigMap>>;

    async fn add_outpoint(&self, outpoint: OutPoint) -> DbResult<bool>;

    async fn selected_outpoints(&self) -> DbResult<HashSet<OutPoint>>;

    async fn add_kickoff_info(&self, deposit_txid: Txid, kickoff_info: KickoffInfo)
        -> DbResult<()>;

    async fn get_kickoff_info(&self, deposit_txid: Txid) -> DbResult<Option<KickoffInfo>>;

    async fn get_checkpoint_index(&self, deposit_txid: Txid) -> DbResult<Option<u64>>;

    async fn set_checkpoint_index(&self, deposit_txid: Txid, checkpoint_idx: u64) -> DbResult<()>;
}
