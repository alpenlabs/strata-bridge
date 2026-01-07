//! This module contains the deposit transaction.

use bitcoin::{
    absolute,
    sighash::{Prevouts, SighashCache},
    transaction::Version,
    Amount, OutPoint, Psbt, ScriptBuf, Transaction, TxIn, TxOut,
};
use secp256k1::schnorr;
use strata_asm_txs_bridge_v1::constants::{BRIDGE_V1_SUBPROTOCOL_ID, DEPOSIT_TX_TYPE};
use strata_codec::Codec;
use strata_l1_txfmt::{MagicBytes, ParseConfig, TagData};

use crate::{
    connectors::{
        prelude::{DepositRequestConnector, NOfNConnector, TimelockedSpendPath, TimelockedWitness},
        Connector,
    },
    transactions::{PresignedTx, SigningInfo},
};

/// Data that is needed to construct a [`DepositTx`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositData {
    /// Deposit index.
    pub deposit_idx: u32,
    /// Outpoint of the deposit request transaction.
    pub deposit_request_outpoint: OutPoint,
    /// Magic bytes that identify the bridge.
    pub magic_bytes: MagicBytes,
}

impl DepositData {
    /// Computes the OP_RETURN leaf script that pushes
    /// the SPS-50 header of the deposit transaction.
    pub fn header_leaf_script(&self) -> ScriptBuf {
        let mut aux_data = Vec::new();
        self.deposit_idx
            .encode(&mut aux_data)
            .expect("deposit index should be encodable");
        let tag_data = TagData::new(BRIDGE_V1_SUBPROTOCOL_ID, DEPOSIT_TX_TYPE, aux_data)
            .expect("aux data should not be too long");

        ParseConfig::new(self.magic_bytes)
            .encode_script_buf(&tag_data.as_ref())
            .expect("encoding should be valid")
    }
}

// TODO: (@uncomputable) Check in unit test that deposit tx can be parsed by ASM code
// https://github.com/alpenlabs/alpen/blob/b016495114050409e831898436d7d0ac04df8d82/crates/asm/txs/bridge-v1/src/deposit/parse.rs#L85
/// The deposit transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositTx {
    psbt: Psbt,
    prevouts: [TxOut; Self::N_INPUTS],
    deposit_connector: NOfNConnector,
    deposit_request_connector: DepositRequestConnector,
}

impl DepositTx {
    /// Index of the SPS-50 header output.
    pub const HEADER_VOUT: u32 = 0;
    /// Index of the deposit connector.
    pub const DEPOSIT_VOUT: u32 = 1;
    /// Number of transaction inputs.
    pub const N_INPUTS: usize = 1;

    /// Creates a deposit transaction.
    pub fn new(
        data: DepositData,
        deposit_connector: NOfNConnector,
        deposit_request_connector: DepositRequestConnector,
    ) -> Self {
        debug_assert!(deposit_connector.network() == deposit_request_connector.network());
        debug_assert!(deposit_connector.internal_key() == deposit_request_connector.internal_key());

        let prevouts = [deposit_request_connector.tx_out()];
        let input = vec![TxIn {
            previous_output: data.deposit_request_outpoint,
            sequence: deposit_request_connector.sequence(TimelockedSpendPath::Normal),
            ..Default::default()
        }];
        let output = vec![
            TxOut {
                script_pubkey: data.header_leaf_script(),
                value: Amount::ZERO,
            },
            deposit_connector.tx_out(),
        ];
        let tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("witness should be empty");

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
        }

        Self {
            psbt,
            prevouts,
            deposit_connector,
            deposit_request_connector,
        }
    }

    /// Finalizes the transaction with the given witness data.
    pub fn finalize(self, n_of_n_signature: schnorr::Signature) -> Transaction {
        let mut psbt = self.psbt;
        let deposit_request_witness = TimelockedWitness::Normal {
            output_key_signature: n_of_n_signature,
        };
        self.deposit_request_connector
            .finalize_input(&mut psbt.inputs[0], &deposit_request_witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}

impl PresignedTx<{ Self::N_INPUTS }> for DepositTx {
    fn signing_info(&self) -> [SigningInfo; Self::N_INPUTS] {
        let mut cache = SighashCache::new(&self.psbt.unsigned_tx);
        [self.deposit_request_connector.get_signing_info(
            &mut cache,
            Prevouts::All(&self.prevouts),
            TimelockedSpendPath::Normal,
            0,
        )]
    }
}

impl AsRef<Transaction> for DepositTx {
    fn as_ref(&self) -> &Transaction {
        &self.psbt.unsigned_tx
    }
}
