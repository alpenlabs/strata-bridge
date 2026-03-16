//! This module contains the withdrawal fulfillment transaction.

use bitcoin::{absolute, transaction::Version, Amount, ScriptBuf, Transaction, TxOut};
use strata_asm_txs_bridge_v1::withdrawal_fulfillment::WithdrawalFulfillmentTxHeaderAux;
use strata_l1_txfmt::{MagicBytes, ParseConfig};
use strata_primitives::bitcoin_bosd::Descriptor;

/// Data needed to construct an unfunded [`WithdrawalFulfillmentTx`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WithdrawalFulfillmentData {
    /// Deposit index for the SPS-50 header.
    pub deposit_idx: u32,
    /// Amount to send to the user (after operator fee deduction).
    pub user_amount: Amount,
    /// Magic bytes that identify the bridge.
    pub magic_bytes: MagicBytes,
}

impl WithdrawalFulfillmentData {
    /// Computes the OP_RETURN leaf script that pushes
    /// the SPS-50 header of the withdrawal fulfillment transaction.
    pub fn header_leaf_script(&self) -> ScriptBuf {
        let tag_data = WithdrawalFulfillmentTxHeaderAux::new(self.deposit_idx).build_tag_data();
        ParseConfig::new(self.magic_bytes)
            .encode_script_buf(&tag_data.as_ref())
            .expect("encoding should be valid")
    }
}

// TODO: (@uncomputable) Check in unit test that withdrawal fulfillment tx can be parsed by ASM code
// https://github.com/alpenlabs/alpen/blob/b016495114050409e831898436d7d0ac04df8d82/crates/asm/txs/bridge-v1/src/withdrawal_fulfillment/parse.rs#L63
/// The withdrawal fulfillment transaction.
///
/// This is an unfunded transaction with outputs only. The wallet will add
/// inputs and change during funding.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct WithdrawalFulfillmentTx(Transaction);

impl WithdrawalFulfillmentTx {
    /// Index of the SPS-50 header output.
    pub const HEADER_VOUT: u32 = 0;
    /// Index of the user withdrawal output.
    pub const USER_VOUT: u32 = 1;
    /// Index of the change output, if it exists.
    pub const OPTIONAL_CHANGE_VOUT: u32 = 2;

    /// Creates an unfunded withdrawal fulfillment transaction.
    ///
    /// The transaction has outputs only (header and user payment).
    /// Inputs and change will be added by the wallet during funding.
    pub fn new(data: WithdrawalFulfillmentData, user_descriptor: Descriptor) -> Self {
        let header_leaf_script = data.header_leaf_script();

        let output = vec![
            TxOut {
                script_pubkey: header_leaf_script,
                value: Amount::ZERO,
            },
            TxOut {
                script_pubkey: user_descriptor.to_script(),
                value: data.user_amount,
            },
        ];

        let tx = Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output,
        };

        Self(tx)
    }

    /// Returns the inner bitcoin transaction.
    ///
    /// The transaction needs to be funded and signed before it can be broadcast.
    pub fn into_unsigned_tx(self) -> Transaction {
        self.0
    }
}

impl AsRef<Transaction> for WithdrawalFulfillmentTx {
    fn as_ref(&self) -> &Transaction {
        &self.0
    }
}
