//! This module contains the CPFP connector.

use bitcoin::{
    taproot::TaprootSpendInfo, Address, Amount, Network, ScriptBuf, Witness, WitnessProgram,
};

use crate::connectors::{Connector, TaprootWitness};

/// CPFP connector that uses the P2A locking script.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct CpfpConnector {
    network: Network,
}

impl CpfpConnector {
    /// Creates a new connector.
    pub const fn new(network: Network) -> Self {
        Self { network }
    }
}

// We want to implement the [`Connector`] trait because it provides a unit testing interface.
// Because P2A is not a Taproot output, we have to be creative in how we implement the methods.
impl Connector for CpfpConnector {
    type Witness = ();

    fn network(&self) -> Network {
        self.network
    }

    fn value(&self) -> Amount {
        Amount::ZERO
    }

    fn address(&self) -> Address {
        Address::from_witness_program(WitnessProgram::p2a(), self.network)
    }

    fn script_pubkey(&self) -> bitcoin::ScriptBuf {
        let witness_program = WitnessProgram::p2a();
        ScriptBuf::new_witness_program(&witness_program)
    }

    fn spend_info(&self) -> TaprootSpendInfo {
        panic!("P2A is not a taproot output")
    }

    fn get_taproot_witness(&self, _witness: &Self::Witness) -> TaprootWitness {
        panic!("P2A is not a taproot output")
    }

    fn finalize_input(&self, input: &mut bitcoin::psbt::Input, _witness: &Self::Witness) {
        input.final_script_witness = Some(Witness::default());
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{absolute, transaction, OutPoint, Transaction, TxOut};
    use strata_bridge_primitives::scripts::prelude::create_tx_ins;

    use super::*;
    use crate::connectors::test_utils::BitcoinNode;

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
        //               | 0 sat: P2A
        let connector = CpfpConnector::new(Network::Regtest);
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

        // Submit parent and child in the same package
        node.submit_package(&[signed_parent_tx, signed_child_tx]);
    }
}
