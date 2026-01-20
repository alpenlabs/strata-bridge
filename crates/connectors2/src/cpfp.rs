//! This module contains the CPFP connector.

use bitcoin::{psbt::Input, Address, Amount, Network, ScriptBuf, TxOut, Witness, WitnessProgram};

/// CPFP connector that uses the P2A locking script.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct CpfpConnector {
    network: Network,
    value: Amount,
}

impl CpfpConnector {
    /// Creates a new connector.
    pub const fn new(network: Network, value: Amount) -> Self {
        Self { network, value }
    }

    /// Returns the network of the connector.
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Returns the value of the connector.
    pub const fn value(&self) -> Amount {
        self.value
    }

    /// Generates the address of the connector.
    pub fn address(&self) -> Address {
        Address::from_witness_program(WitnessProgram::p2a(), self.network)
    }

    /// Generates the script pubkey of the connector.
    pub fn script_pubkey(&self) -> ScriptBuf {
        ScriptBuf::new_p2a()
    }

    /// Generates the transaction output of the connector.
    pub fn tx_out(&self) -> TxOut {
        TxOut {
            value: self.value(),
            script_pubkey: self.address().script_pubkey(),
        }
    }

    /// Finalizes the PSBT `input` where the connector is used.
    pub fn finalize_input(&self, input: &mut Input) {
        input.final_script_witness = Some(Witness::default());
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{absolute, transaction, OutPoint, Transaction, TxOut};
    use strata_bridge_primitives::scripts::prelude::create_tx_ins;

    use super::*;
    use crate::test_utils::BitcoinNode;

    #[test]
    fn p2a_spend() {
        let mut node = BitcoinNode::new();

        // Create the parent transaction that funds the P2A connector.
        // The parent transaction is v3 and has zero fees.
        //
        // inputs        | outputs
        // --------------+--------------
        // N sat: wallet | N sat: wallet
        //               |--------------
        //               | 0 sat: P2A (CPFP)
        let connector = CpfpConnector::new(Network::Regtest, Amount::ZERO);
        let input = create_tx_ins([node.next_coinbase_outpoint()]);
        let output = vec![
            TxOut {
                value: node.coinbase_amount(),
                script_pubkey: node.wallet_address().script_pubkey(),
            },
            connector.tx_out(),
        ];
        let parent_tx = Transaction {
            version: transaction::Version(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };
        let signed_parent_tx = node.sign(&parent_tx);

        // Create the child transaction that spends the P2A connector of the parent transaction.
        // The child transaction is v3 and pays 2 * fees: for the itself and for the parent.
        //
        // inputs        | outputs
        // --------------+------------------------
        // 0 sat: P2A    | N - fee * 2 sat: wallet
        // --------------|
        // N sat: wallet |
        let input = create_tx_ins([
            OutPoint {
                txid: signed_parent_tx.compute_txid(),
                vout: 1,
            },
            node.next_coinbase_outpoint(),
        ]);
        let fee = Amount::from_sat(1_000);
        let output = vec![TxOut {
            value: node.coinbase_amount() - fee * 2,
            script_pubkey: node.wallet_address().script_pubkey(),
        }];
        let child_tx = Transaction {
            version: transaction::Version(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };
        let signed_child_tx = node.sign(&child_tx);

        node.submit_package(&[signed_parent_tx, signed_child_tx]);
    }
}
