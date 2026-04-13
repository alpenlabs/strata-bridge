//! Constructs and finalizes withdrawal fulfillment transactions.

use alpen_bridge_params::types::Tag;
use bitcoin::{consensus, Amount, OutPoint, Transaction, TxOut, Txid};
use bitcoin_bosd::Descriptor;

use super::scripts::general::{create_tx, create_tx_ins, create_tx_outs, op_return_nonce};

pub(super) type OperatorIdx = u32;

/// The transaction by which an operator fronts payments to a user requesting a withdrawal.
#[derive(Debug, Clone)]
pub(super) struct WithdrawalFulfillment(Transaction);

/// Metadata to be posted in the withdrawal transaction.
///
/// This metadata is used to identify the operator and deposit index in the bridge withdrawal proof.
#[derive(Debug, Clone)]
pub(super) struct WithdrawalMetadata {
    /// The tag used to mark the withdrawal metadata transaction.
    pub tag: Tag,

    /// The index of the operator as per the information in the chain state in Strata.
    ///
    /// This is required in order to link a withdrawal fulfillment transaction to an operator so
    /// that the a valid withdrawal fulfillment transaction by one operator cannot be used in the
    /// proof of another operator, and to ensure that the operators only process withdrawal
    /// requests assigned to themselves. Part of these enforcements happen through the proof
    /// statements where the operator is required to sign the txid of the withdrawal
    /// fulfillment transaction.
    pub operator_idx: OperatorIdx,

    /// The index of the deposit as per the information in the chain state in Strata.
    ///
    /// This is required in order to link a withdrawal fulfillment transaction to a deposit so that
    /// two withdrawal requests that are otherwise identical (same address, same period, same
    /// operator) cannot be used to withdrawal two different bridged-in UTXOs off of the same
    /// withdrawal fulfillment transaction.
    pub deposit_idx: u32,

    /// The txid of the deposit UTXO that can be withdrawn via this withdrawal fulfillment.
    ///
    /// This is required for tying the peg-out graph with the deposit txid being claimed by just
    /// inspecting the withdrawal fulfillment transaction itself. This serves the same purpose as
    /// the `deposit_idx` field. However, the `deposit_txid` is a more direct way of linking the
    /// two since the `deposit_idx` is computed after the fact when the deposit transaction is
    /// confirmed on chain.
    pub deposit_txid: Txid,
}

impl WithdrawalMetadata {
    /// Returns the op-return data for the withdrawal metadata.
    pub(super) fn op_return_data(&self) -> Vec<u8> {
        let op_id_prefix: [u8; 4] = self.operator_idx.to_be_bytes();
        let deposit_id_prefix: [u8; 4] = self.deposit_idx.to_be_bytes();
        let deposit_txid_data = consensus::encode::serialize(&self.deposit_txid);
        [
            self.tag.as_bytes(),
            &op_id_prefix[..],
            &deposit_id_prefix[..],
            &deposit_txid_data[..],
        ]
        .concat()
        .to_vec()
    }
}

impl WithdrawalFulfillment {
    /// Constructs a new instance of the withdrawal transaction.
    ///
    /// NOTE: This transaction is not signed and must be done so before broadcasting by calling
    /// `signrawtransaction` on the Bitcoin Core RPC, for example.
    pub(super) fn new(
        metadata: WithdrawalMetadata,
        sender_outpoints: Vec<OutPoint>,
        amount: Amount,
        change: Option<TxOut>,
        recipient_desc: Descriptor,
    ) -> Self {
        let tx_ins = create_tx_ins(sender_outpoints);
        let recipient_pubkey = recipient_desc.to_script();

        let op_return_amount = Amount::from_int_btc(0);

        let op_return_data = metadata.op_return_data();
        let op_return_script = op_return_nonce(&op_return_data);

        let mut scripts_and_amounts = vec![
            (recipient_pubkey, amount),
            (op_return_script, op_return_amount),
        ];

        if let Some(change) = change {
            let TxOut {
                value,
                script_pubkey,
            } = change;
            scripts_and_amounts.push((script_pubkey, value));
        }

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let tx = create_tx(tx_ins.clone(), tx_outs);

        Self(tx)
    }

    /// Getter for the underlying transaction.
    pub(super) fn tx(self) -> Transaction {
        self.0
    }
}
