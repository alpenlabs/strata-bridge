//! This module contains the CPFP connector.

use bitcoin::{taproot::TaprootSpendInfo, Address, Amount, Network, ScriptBuf, WitnessProgram};

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

    fn finalize_input(&self, _input: &mut bitcoin::psbt::Input, _witness: &Self::Witness) {
        // Do nothing
    }
}

#[cfg(test)]
mod tests {
    use secp256k1::Message;

    use super::*;
    use crate::connectors::test_utils::Signer;

    struct P2ASigner;

    impl Signer for P2ASigner {
        type Connector = CpfpConnector;

        fn generate() -> Self {
            Self
        }

        fn get_connector(&self) -> Self::Connector {
            CpfpConnector {
                network: Network::Regtest,
            }
        }

        fn get_connector_name(&self) -> &'static str {
            "p2a"
        }

        fn sign_leaf(
            &self,
            _leaf_index: Option<usize>,
            _sighash: Message,
        ) -> <Self::Connector as Connector>::Witness {
            // Return unit
        }
    }

    #[test]
    #[ignore]
    fn p2a_spend() {
        let leaf_index = None;
        P2ASigner::assert_connector_is_spendable(leaf_index);
    }
}
