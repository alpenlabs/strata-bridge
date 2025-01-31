use bitcoin::{Address, Amount, OutPoint, Transaction};
use bitcoin_bosd::Descriptor;
use strata_bridge_primitives::{
    scripts::general::{create_tx, create_tx_ins, create_tx_outs, op_return_nonce},
    types::OperatorIdx,
};

/// The transaction by which an operator fronts payments to a user requesting a withdrawal.
#[derive(Debug, Clone)]
pub struct WithdrawalFulfillment(Transaction);

/// The change output for the withdrawal transaction.
#[derive(Debug, Clone)]
pub struct WithdrawalChange {
    pub address: Address,
    pub amount: Amount,
}

/// Metadata to be posted in the withdrawal transaction.
///
/// This metadata is used to identify the operator and deposit index in the bridge withdrawal proof.
#[derive(Debug, Clone, Copy)]
pub struct WithdrawalMetadata {
    pub operator_idx: OperatorIdx,
    pub deposit_idx: u32,
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
        change: Option<WithdrawalChange>,
        recipient_desc: Descriptor,
    ) -> Self {
        let tx_ins = create_tx_ins(sender_outpoints);
        let recipient_pubkey = recipient_desc.to_script();

        let op_return_amount = Amount::from_int_btc(0);

        let WithdrawalMetadata {
            operator_idx,
            deposit_idx,
        } = metadata;
        let prefix: [u8; 4] = operator_idx.to_be_bytes();
        let deposit_idx: [u8; 4] = deposit_idx.to_be_bytes();

        let data = [prefix, deposit_idx].concat();

        let op_return_script = op_return_nonce(&data[..]);

        let mut scripts_and_amounts = vec![
            (op_return_script, op_return_amount),
            (recipient_pubkey, amount),
        ];

        if let Some(change) = change {
            let change_pubkey = change.address.script_pubkey();

            scripts_and_amounts.push((change_pubkey, change.amount));
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
    use strata_bridge_test_utils::prelude::{generate_outpoint, generate_xonly_pubkey};

    use super::*;

    #[test]
    fn test_withdrawal_fulfillment_tx() {
        // Set up parameters
        let network = Network::Regtest;
        let sender_outpoints = vec![generate_outpoint(), generate_outpoint()]; // Sample outpoints
        let amount = Amount::from_sat(10000); // Recipient amount
        let change_amount = Amount::from_sat(5000); // Change amount
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
        let operator_idx: u32 = OsRng.gen();
        let deposit_idx: u32 = OsRng.gen();

        let withdrawal_metadata = WithdrawalMetadata {
            operator_idx,
            deposit_idx,
        };
        let change = WithdrawalChange {
            address: change_address.clone(),
            amount: change_amount,
        };
        let withdrawal_fulfillment = WithdrawalFulfillment::new(
            withdrawal_metadata,
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

        let operator_idx = operator_idx.to_be_bytes().to_lower_hex_string();
        let deposit_dx = deposit_idx.to_be_bytes().to_lower_hex_string();
        let data = [operator_idx, deposit_dx].concat();
        assert!(
            tx.output.iter().any(|out| out.value == op_return_amount
                && out.script_pubkey.is_op_return()
                && out.script_pubkey[2..].to_hex_string().starts_with(&data)),
            "OP_RETURN output is missing or invalid"
        );
    }
}
