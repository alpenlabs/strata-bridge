//! This module contains the bridge proof transaction.

use bitcoin::{
    absolute, opcodes, script::PushBytes, transaction::Version, Amount, OutPoint, ScriptBuf,
    Transaction, TxIn, TxOut, Txid,
};

use crate::{
    connectors::{
        prelude::{ContestProofConnector, TimelockedSpendPath},
        Connector,
    },
    transactions::{prelude::ContestTx, AsTransaction},
};

// TODO: (@uncomputable) Finalize structure of public values + proof data
/// Data that is needed to construct a [`BridgeProofTx`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BridgeProofData {
    /// ID of the contest transaction.
    pub contest_txid: Txid,
    /// Public values of the bridge proof.
    pub public_values: Vec<u8>,
    /// The bridge proof in compressed Groth16 format.
    pub proof: Vec<u8>,
}

impl BridgeProofData {
    /// Computes the OP_RETURN leaf script that pushes
    /// the raw bridge proof bytes.
    pub fn header_leaf_script(&self) -> ScriptBuf {
        let mut bytes = self.public_values.clone();
        bytes.extend(&self.proof);
        let pushbytes: &PushBytes = bytes.as_slice().try_into().unwrap();

        ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_RETURN)
            .push_slice(pushbytes)
            .into_script()
    }
}

/// The bridge proof transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BridgeProofTx(Transaction);

impl BridgeProofTx {
    /// Index of the proof data output.
    pub const PROOF_DATA_VOUT: u32 = 0;

    /// Creates a bridge proof transaction.
    pub fn new(data: BridgeProofData, contest_proof_connector: ContestProofConnector) -> Self {
        let input = vec![TxIn {
            previous_output: OutPoint {
                txid: data.contest_txid,
                vout: ContestTx::PROOF_VOUT,
            },
            sequence: contest_proof_connector.sequence(TimelockedSpendPath::Normal),
            ..Default::default()
        }];
        let output = vec![TxOut {
            script_pubkey: data.header_leaf_script(),
            value: Amount::ZERO,
        }];
        let tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };

        Self(tx)
    }

    /// Returns the inner bitcoin transaction.
    ///
    /// The transaction needs to be updated before it can be broadcast:
    /// 1. Extra inputs need to be added to pay for fees.
    /// 2. A change output may need to be added.
    /// 3. All inputs need to be signed.
    ///
    /// # Signing the first transaction input
    ///
    /// Get the signing info via
    /// [`crate::connectors::prelude::ContestProofConnector::signing_info_bridge_proof()`].
    ///
    /// Finalize the input via
    /// [`crate::connectors::prelude::ContestProofConnector::partially_finalize_bridge_proof()`].
    pub fn into_unsigned_tx(self) -> Transaction {
        self.0
    }
}

impl AsTransaction for BridgeProofTx {
    fn as_unsigned_tx(&self) -> &Transaction {
        &self.0
    }
}
