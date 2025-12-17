//! This module contains the deposit transaction.

use bitcoin::{
    absolute, sighash::Prevouts, transaction::Version, Amount, OutPoint, Psbt, ScriptBuf,
    Transaction, TxOut, Txid,
};
use strata_bridge_primitives::scripts::prelude::create_tx_ins;
use strata_codec::Codec;
use strata_l1_txfmt::{MagicBytes, ParseConfig, SubprotocolId, TagData, TxType};

use crate::{
    connectors::{
        prelude::{DepositRequestConnector, NOfNConnector, TimelockedWitness},
        Connector,
    },
    transactions::{PresignedTx, SigningInfo},
};

const MAGIC_BYTES: MagicBytes = *b"alpn";
const SUBPROTOCOL_ID: SubprotocolId = 2;
const DEPOSIT_TX_TYPE: TxType = 1;
const DEPOSIT_REQUEST_DEPOSIT_VOUT: u32 = 1;

/// Data that is needed to construct a [`DepositTx`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositData {
    /// Deposit index.
    pub deposit_idx: u32,
    /// ID of the deposit request transaction.
    pub deposit_request_txid: Txid,
}

impl DepositData {
    /// Computes the OP_RETURN leaf script that pushes
    /// the SPS-50 header of the deposit transaction.
    pub fn header_leaf_script(&self) -> ScriptBuf {
        let mut aux_data = Vec::new();
        self.deposit_idx.encode(&mut aux_data).unwrap();

        let tag_data = TagData::new(SUBPROTOCOL_ID, DEPOSIT_TX_TYPE, aux_data).unwrap();
        ParseConfig::new(MAGIC_BYTES)
            .encode_script_buf(&tag_data.as_ref())
            .unwrap()
    }
}

/// The deposit transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DepositTx {
    psbt: Psbt,
    prevouts: [TxOut; 1],
    deposit_connector: NOfNConnector,
    deposit_request_connector: DepositRequestConnector,
}

impl DepositTx {
    /// Index of the SPS-50 header output.
    pub const HEADER_VOUT: u32 = 0;
    /// Index of the deposit connector.
    pub const DEPOSIT_VOUT: u32 = 1;

    /// Creates a deposit transaction.
    pub fn new(
        data: DepositData,
        deposit_connector: NOfNConnector,
        deposit_request_connector: DepositRequestConnector,
    ) -> Self {
        debug_assert!(deposit_connector.internal_key() == deposit_request_connector.internal_key());

        let utxos = [OutPoint {
            txid: data.deposit_request_txid,
            vout: DEPOSIT_REQUEST_DEPOSIT_VOUT,
        }];
        let prevouts = [deposit_request_connector.tx_out()];
        let input = create_tx_ins(utxos);
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
}

impl PresignedTx<1> for DepositTx {
    type ExtraWitness = ();

    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn get_signing_info(
        &self,
        cache: &mut bitcoin::sighash::SighashCache<&Transaction>,
        input_index: usize,
    ) -> SigningInfo {
        match input_index {
            0 => self.deposit_request_connector.deposit_signing_info(
                cache,
                Prevouts::All(&self.prevouts),
                input_index,
            ),
            _ => panic!("Input index is out of bounds"),
        }
    }

    fn finalize(
        self,
        n_of_n_signatures: [secp256k1::schnorr::Signature; 1],
        _extra: &Self::ExtraWitness,
    ) -> Transaction {
        let mut psbt = self.psbt;
        let deposit_request_witness = TimelockedWitness::Normal {
            output_key_signature: n_of_n_signatures[0],
        };
        self.deposit_request_connector
            .finalize_input(&mut psbt.inputs[0], &deposit_request_witness);

        psbt.extract_tx().expect("should be able to extract tx")
    }
}
