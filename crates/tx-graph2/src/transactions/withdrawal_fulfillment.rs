//! This module contains the withdrawal fulfillment transaction.

use bitcoin::{absolute, transaction::Version, Amount, OutPoint, ScriptBuf, Transaction, TxOut};
use strata_asm_txs_bridge_v1::constants::{
    BRIDGE_V1_SUBPROTOCOL_ID, WITHDRAWAL_FULFILLMENT_TX_TYPE,
};
use strata_bridge_primitives::scripts::prelude::create_tx_ins;
use strata_codec::Codec;
use strata_l1_txfmt::{MagicBytes, ParseConfig, TagData};
use strata_primitives::bitcoin_bosd::Descriptor;

/// Data that is needed to construct a [`WithdrawalFulfillmentTx`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WithdrawalFulfillmentData {
    /// Deposit index.
    pub deposit_idx: u32,
    /// Operator-controlled UTXOs that fund the withdrawal fulfillment.
    ///
    /// These are the transaction inputs.
    pub withdrawal_funds: Vec<OutPoint>,
    /// Sum of input values.
    pub input_amount: Amount,
    /// Optional output where the operator receives their change.
    ///
    /// The deposit amount is equal to the input value minus the change value.
    pub change_output: Option<TxOut>,
    /// Magic bytes that identify the bridge.
    pub magic_bytes: MagicBytes,
}

impl WithdrawalFulfillmentData {
    /// Computes the OP_RETURN leaf script that pushes
    /// the SPS-50 header of the withdrawal fulfillment transaction.
    pub fn header_leaf_script(&self) -> ScriptBuf {
        let mut aux_data = Vec::new();
        self.deposit_idx
            .encode(&mut aux_data)
            .expect("deposit index should be encodable");
        let tag_data = TagData::new(
            BRIDGE_V1_SUBPROTOCOL_ID,
            WITHDRAWAL_FULFILLMENT_TX_TYPE,
            aux_data,
        )
        .expect("aux data should not be too long");

        ParseConfig::new(self.magic_bytes)
            .encode_script_buf(&tag_data.as_ref())
            .expect("encoding should be valid")
    }
}

// TODO: (@uncomputable) Check in unit test that withdrawal fulfillment tx can be parsed by ASM code
// https://github.com/alpenlabs/alpen/blob/b016495114050409e831898436d7d0ac04df8d82/crates/asm/txs/bridge-v1/src/withdrawal_fulfillment/parse.rs#L63
/// The withdrawal fulfillment transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WithdrawalFulfillmentTx(Transaction);

impl WithdrawalFulfillmentTx {
    /// Index of the SPS-50 header output.
    pub const HEADER_VOUT: u32 = 0;
    /// Index of the user withdrawal output.
    pub const USER_VOUT: u32 = 1;
    /// Index of the CPFP output, if it exists.
    pub const OPTIONAL_CPFP_VOUT: u32 = 2;

    /// Creates a withdrawal fulfillment transaction.
    pub fn new(data: WithdrawalFulfillmentData, user_descriptor: Descriptor) -> Self {
        let header_leaf_script = data.header_leaf_script();
        let input = create_tx_ins(data.withdrawal_funds);
        let mut output = vec![
            TxOut {
                script_pubkey: header_leaf_script,
                value: Amount::ZERO,
            },
            TxOut {
                script_pubkey: user_descriptor.to_script(),
                value: data.input_amount
                    - data
                        .change_output
                        .as_ref()
                        .map(|x| x.value)
                        .unwrap_or_default(),
            },
        ];
        output.extend(data.change_output);

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
    /// The transaction needs to be signed before it can be broadcast.
    pub fn into_unsigned_tx(self) -> Transaction {
        self.0
    }
}
