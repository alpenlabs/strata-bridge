//! This module contains a custom CPFP connector.

use bitcoin::{Address, Amount, Network, ScriptBuf, TxOut};
use bitcoin_bosd::Descriptor;

/// CPFP connector that uses a custom locking script.
///
/// Because of the custom locking script,
/// the input where this connector is spent requires a custom witness.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CpfpConnector {
    network: Network,
    address: Address,
}

impl CpfpConnector {
    /// Creates a new connector.
    ///
    /// This method returns `None` if the descriptor has no address (OP_RETURN).
    pub fn new(network: Network, descriptor: &Descriptor) -> Option<Self> {
        let address = descriptor.to_address(network).ok()?;

        Some(Self { network, address })
    }

    /// Returns the network of the connector.
    pub const fn network(&self) -> Network {
        self.network
    }

    /// Returns the value of the connector.
    pub const fn value(&self) -> Amount {
        Amount::ZERO
    }

    /// Returns the address of the connector.
    pub fn address(&self) -> Address {
        self.address.clone()
    }

    /// Returns the script pubkey of the connector.
    pub fn script_pubkey(&self) -> ScriptBuf {
        self.address().script_pubkey()
    }

    /// Generates the transaction output of the connector.
    pub fn tx_out(&self) -> TxOut {
        TxOut {
            value: self.value(),
            script_pubkey: self.script_pubkey(),
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{absolute, transaction, OutPoint, Transaction, TxOut};
    use strata_bridge_primitives::scripts::prelude::create_tx_ins;

    use super::*;
    use crate::test_utils::BitcoinNode;

    const FEE: Amount = Amount::from_sat(1000);

    #[test]
    fn custom_cpfp_spend() {
        let mut node = BitcoinNode::new();
        let descriptor = Descriptor::try_from(node.wallet_address().clone()).unwrap();
        let connector = CpfpConnector::new(Network::Regtest, &descriptor)
            .expect("descriptor should have address");

        // The parent transaction is v3 and has zero fees.
        //
        // inputs        | outputs
        // --------------+-------------------------
        // N sat: wallet | N sat: wallet
        //               |-------------------------
        //               | 0 sat: descriptor (CPFP)
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

        // The child transaction is v3 and pays 2 * fees: for the itself and for the parent.
        //
        // inputs            | outputs
        // ------------------+------------------------
        // 0 sat: descriptor | N - FEE * 2 sat: wallet
        // ------------------|
        // N sat: wallet     |
        let prevouts = vec![connector.tx_out(), node.coinbase_tx_out()];
        let input = create_tx_ins([
            OutPoint {
                txid: signed_parent_tx.compute_txid(),
                vout: 1,
            },
            node.next_coinbase_outpoint(),
        ]);
        let output = vec![TxOut {
            value: node.coinbase_amount() - FEE * 2,
            script_pubkey: node.wallet_address().script_pubkey(),
        }];
        let child_tx = Transaction {
            version: transaction::Version(3),
            lock_time: absolute::LockTime::ZERO,
            input,
            output,
        };
        let signed_child_tx = node.sign_with_prevouts(&child_tx, &prevouts);

        node.submit_package(&[signed_parent_tx, signed_child_tx]);
    }
}
