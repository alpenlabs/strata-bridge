//! This module contains connectors for the Glock transaction graph.

pub mod claim_contest;
pub mod claim_payout;
pub mod cpfp;
pub mod n_of_n;
pub mod prelude;
pub mod timelocked_n_of_nr;

#[cfg(test)]
pub mod test_utils;

use bitcoin::{
    psbt::Input,
    taproot::{LeafVersion, TaprootSpendInfo},
    Address, Amount, Network, ScriptBuf, TxOut,
};
use secp256k1::{schnorr, XOnlyPublicKey};
use strata_bridge_primitives::scripts::prelude::{create_taproot_addr, finalize_input, SpendPath};
use strata_primitives::constants::UNSPENDABLE_PUBLIC_KEY;

/// A connector output.
pub trait Connector {
    /// Witness data that is required to spend the connector.
    type Witness;

    /// Returns the network of the connector.
    fn network(&self) -> Network;

    /// Returns the internal key of the connector.
    ///
    /// The key will be unspendable for connectors without a key path spend.
    fn internal_key(&self) -> XOnlyPublicKey {
        *UNSPENDABLE_PUBLIC_KEY
    }

    /// Generates the vector of leaf scripts of the connector.
    ///
    /// The vector will be empty for connectors without script path spends.
    fn leaf_scripts(&self) -> Vec<ScriptBuf> {
        Vec::new()
    }

    /// Returns the value of the connector.
    fn value(&self) -> Amount;

    /// Generates the address of the connector.
    fn address(&self) -> Address {
        create_taproot_addr(
            &self.network(),
            SpendPath::Both {
                internal_key: self.internal_key(),
                scripts: self.leaf_scripts().as_slice(),
            },
        )
        .expect("tap tree is valid")
        .0
    }

    /// Generates the script pubkey of the connector.
    fn script_pubkey(&self) -> ScriptBuf {
        self.address().script_pubkey()
    }

    /// Generates the transaction output of the connector.
    fn tx_out(&self) -> TxOut {
        TxOut {
            value: self.value(),
            script_pubkey: self.address().script_pubkey(),
        }
    }

    /// Generates the taproot spend info of the connector.
    fn spend_info(&self) -> TaprootSpendInfo {
        // It seems wasteful to have almost the same function body as [`Connector::address`],
        // but in practice we only ever need one of the two: the address or the spend info.
        // We may want to reimplement `create_taproot_addr` to reduce code duplication.
        create_taproot_addr(
            &self.network(),
            SpendPath::Both {
                internal_key: self.internal_key(),
                scripts: self.leaf_scripts().as_slice(),
            },
        )
        .expect("tap tree is valid")
        .1
    }

    /// Converts the witness into a generic taproot witness.
    fn get_taproot_witness(&self, witness: &Self::Witness) -> TaprootWitness;

    /// Finalizes the PSBT `input` where the connector is used, using the provided `witness`.
    ///
    /// # Warning
    ///
    /// If the connector uses relative timelocks,
    /// then the **sequence** field of the transaction input
    /// and the **locktime** field of the transaction must be updated accordingly.
    fn finalize_input(&self, input: &mut Input, witness: &Self::Witness) {
        match self.get_taproot_witness(witness) {
            TaprootWitness::Key {
                output_key_signature,
            } => {
                finalize_input(input, [output_key_signature.serialize().to_vec()]);
            }
            TaprootWitness::Script {
                leaf_index,
                script_inputs,
            } => {
                let mut leaf_scripts = self.leaf_scripts();
                assert!(
                    leaf_index < leaf_scripts.len(),
                    "leaf index should be within bounds"
                );
                let leaf_script = leaf_scripts.swap_remove(leaf_index);
                let script_ver = (leaf_script, LeafVersion::TapScript);
                let taproot_spend_info = self.spend_info();
                let control_block = taproot_spend_info
                    .control_block(&script_ver)
                    .expect("leaf script exists");
                let leaf_script = script_ver.0;

                let mut witness = script_inputs;
                witness.push(leaf_script.to_bytes());
                witness.push(control_block.serialize());
                finalize_input(input, witness);
            }
        }
    }
}

/// Generic Taproot witness data.
///
/// The leaf script and control block are supplied by the connector.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaprootWitness {
    /// Key-path spend.
    Key {
        /// Signature of the output key.
        output_key_signature: schnorr::Signature,
    },
    /// Script-path spend
    Script {
        /// Leaf index.
        leaf_index: usize,
        /// Inputs to the leaf script.
        script_inputs: Vec<Vec<u8>>,
    },
}
