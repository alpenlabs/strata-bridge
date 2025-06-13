//! This module defines the OperatorDb trait, which is used to interact with the operator's
//! database.

use std::collections::BTreeMap;

use arbitrary::Arbitrary;
use async_trait::async_trait;
use bitcoin::{hashes::Hash, Amount, OutPoint, ScriptBuf, TxOut, Txid};
use musig2::{AggNonce, PartialSignature, PubNonce};
use strata_bridge_primitives::{
    bitcoin::BitcoinAddress, scripts::taproot::TaprootWitness, types::OperatorIdx,
};

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
