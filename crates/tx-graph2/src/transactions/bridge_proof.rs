//! This module contains the bridge proof transaction.

use std::num::NonZero;

use bitcoin::{
    absolute, opcodes,
    script::PushBytes,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, OutPoint, Psbt, ScriptBuf, Transaction, TxIn, TxOut, Txid,
};
use secp256k1::{schnorr, Scalar};
use strata_bridge_connectors2::{
    prelude::{ContestProofConnector, TimelockedSpendPath, TimelockedWitness},
    Connector, SigningInfo,
};

use crate::transactions::prelude::ContestTx;

/// Data that is needed to construct a [`BridgeProofTx`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BridgeProofData {
    /// ID of the contest transaction.
    pub contest_txid: Txid,
    /// The serialized bridge proof, including public values.
    pub proof_bytes: Vec<u8>,
    /// Game index.
    pub game_index: NonZero<u32>,
}

/// The bridge proof transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BridgeProofTx {
    // invariant: tx.output[0].script_pubkey == header_leaf_script(&proof_bytes)
    tx: Transaction,
    // invariant: tx.input.len() == prevouts.len()
    prevouts: Vec<TxOut>,
    game_index: NonZero<u32>,
    contest_proof_connector: ContestProofConnector,
}

/// Computes the OP_RETURN leaf script that pushes
/// the raw bridge proof bytes.
fn header_leaf_script(proof_bytes: &[u8]) -> ScriptBuf {
    let pushbytes: &PushBytes = proof_bytes.try_into().unwrap();

    ScriptBuf::builder()
        .push_opcode(opcodes::all::OP_RETURN)
        .push_slice(pushbytes)
        .into_script()
}

impl BridgeProofTx {
    /// Index of the proof data output.
    pub const PROOF_DATA_VOUT: u32 = 0;

    /// Creates a bridge proof transaction.
    pub fn new(data: BridgeProofData, contest_proof_connector: ContestProofConnector) -> Self {
        let prevouts = vec![contest_proof_connector.tx_out()];
        let input = vec![TxIn {
            previous_output: OutPoint {
                txid: data.contest_txid,
                vout: ContestTx::PROOF_VOUT,
            },
            sequence: contest_proof_connector.sequence(TimelockedSpendPath::Normal),
            ..Default::default()
        }];
        let output = vec![TxOut {
            script_pubkey: header_leaf_script(&data.proof_bytes),
            value: Amount::ZERO,
        }];
        let tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        Self {
            tx,
            prevouts,
            game_index: data.game_index,
            contest_proof_connector,
        }
    }

    /// Pushes an input to the transaction.
    pub fn push_input(&mut self, input: TxIn, prevout: TxOut) {
        self.tx.input.push(input);
        self.prevouts.push(prevout);
    }

    /// Pushes an output to the transaction.
    pub fn push_output(&mut self, output: TxOut) {
        self.tx.output.push(output);
    }

    /// Returns the signing info for the first transaction input.
    ///
    /// The signing operator key must be tweaked with the scalar
    /// that is returned by [`Self::operator_key_tweak()`].
    pub fn signing_info_partial(&self) -> SigningInfo {
        let mut cache = SighashCache::new(&self.tx);
        let prevouts = Prevouts::All(&self.prevouts);

        self.contest_proof_connector.get_signing_info(
            &mut cache,
            prevouts,
            TimelockedSpendPath::Normal,
            0,
        )
    }

    /// Returns the scalar that the operator key must be tweaked with.
    ///
    /// The tweak is based on the game index.
    /// It is a normal tweak (by a scalar) and not a tap tweak (by a tap hash).
    pub fn operator_key_tweak(&self) -> Scalar {
        ContestProofConnector::operator_key_tweak(self.game_index)
    }

    /// Signs the first transaction input and returns the resulting bitcoin transaction.
    ///
    /// The remaining inputs must be manually signed.
    pub fn finalize_partial(self, operator_signature: schnorr::Signature) -> Transaction {
        let mut psbt = Psbt::from_unsigned_tx(self.tx).expect("witness should be empty");
        for (input, utxo) in psbt.inputs.iter_mut().zip(self.prevouts) {
            input.witness_utxo = Some(utxo);
        }

        let bridge_proof_witness = TimelockedWitness::Normal {
            output_key_signature: operator_signature,
        };
        self.contest_proof_connector
            .finalize_input(&mut psbt.inputs[0], &bridge_proof_witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl AsRef<Transaction> for BridgeProofTx {
    fn as_ref(&self) -> &Transaction {
        &self.tx
    }
}
