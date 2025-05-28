use alpen_bridge_params::types::Tag;
use bitcoin::{consensus, Amount, OutPoint, Transaction, TxOut, Txid};
use bitcoin_bosd::Descriptor;
use strata_bridge_primitives::{
    scripts::general::{create_tx, create_tx_ins, create_tx_outs, op_return_nonce},
    types::OperatorIdx,
};

/// The transaction by which an operator fronts payments to a user requesting a withdrawal.
#[derive(Debug, Clone)]
pub struct WithdrawalFulfillment(Transaction);

/// Metadata to be posted in the withdrawal transaction.
///
/// This metadata is used to identify the operator and deposit index in the bridge withdrawal proof.
#[derive(Debug, Clone)]
pub struct WithdrawalMetadata {
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
    pub fn op_return_data(&self) -> Vec<u8> {
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
    pub fn new(
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
    pub fn tx(self) -> Transaction {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        address::Address,
        hex::DisplayHex,
        key::{
            rand::{self, Rng},
            TapTweak,
        },
        network::Network,
        Amount,
    };
    use secp256k1::{rand::rngs::OsRng, Keypair, XOnlyPublicKey, SECP256K1};
    use strata_bridge_test_utils::prelude::{
        generate_outpoint, generate_txid, generate_xonly_pubkey,
    };

    use super::*;

    #[test]
    fn test_withdrawal_fulfillment_tx() {
        // Set up parameters
        let network = Network::Regtest;
        let sender_outpoints = vec![generate_outpoint(), generate_outpoint()]; // Sample outpoints
        let amount = Amount::from_sat(10_000); // Recipient amount
        let change_amount = Amount::from_sat(5_000); // Change amount
        let recipient_key = generate_xonly_pubkey();
        let recipient_addr =
            Address::p2tr_tweaked(recipient_key.dangerous_assume_tweaked(), network);
        let recipient_desc = recipient_addr.into();

        // Use a random change address
        let change_keypair = Keypair::new(SECP256K1, &mut rand::thread_rng());
        let change_address = Address::p2tr(
            SECP256K1,
            XOnlyPublicKey::from_keypair(&change_keypair).0,
            None,
            network,
        );

        // Call the `new` function to create a transaction
        let operator_idx: OperatorIdx = OsRng.gen();
        let deposit_idx: u32 = OsRng.gen();
        let deposit_txid = generate_txid();

        let tag = Tag::new([b'a', b'l', b'p', b'0']);
        let withdrawal_metadata = WithdrawalMetadata {
            tag,
            operator_idx,
            deposit_idx,
            deposit_txid,
        };
        let change = TxOut {
            script_pubkey: change_address.script_pubkey(),
            value: change_amount,
        };
        let withdrawal_fulfillment = WithdrawalFulfillment::new(
            withdrawal_metadata.clone(),
            sender_outpoints,
            amount,
            Some(change),
            recipient_desc,
        );

        // Extract the transaction from the returned struct
        let tx = withdrawal_fulfillment.tx();

        // Verify the outputs contain the recipient, change, and OP_RETURN with expected values
        let change_pubkey = change_address.script_pubkey();
        let op_return_amount = Amount::from_int_btc(0);

        assert!(
            tx.output
                .iter()
                .any(
                    |out| out.script_pubkey[2..].to_hex_string() == recipient_key.to_string()
                        && out.value == amount
                ),
            "Recipient output is missing or incorrect"
        );
        assert!(
            tx.output
                .iter()
                .any(|out| out.script_pubkey == change_pubkey && out.value == change_amount),
            "Change output is missing or incorrect"
        );

        let tag = withdrawal_metadata.tag.as_bytes().to_lower_hex_string();
        let operator_idx = withdrawal_metadata
            .operator_idx
            .to_be_bytes()
            .to_lower_hex_string();
        let deposit_idx = withdrawal_metadata
            .deposit_idx
            .to_be_bytes()
            .to_lower_hex_string();
        let deposit_txid = consensus::encode::serialize_hex(&withdrawal_metadata.deposit_txid);

        let second_output = tx.tx_out(1).expect("must have second output");
        assert!(
            second_output.value == op_return_amount
                && second_output.script_pubkey.is_op_return()
                && second_output.script_pubkey[2..].to_hex_string()
                    == format!("{}{}{}{}", tag, operator_idx, deposit_idx, deposit_txid),
            "OP_RETURN output is missing or invalid"
        );
    }
}
