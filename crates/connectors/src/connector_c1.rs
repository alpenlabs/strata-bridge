//! This module contains the connector for the second output of the Claim Transaction.
//!
//! This connector is used to challenge the operator in case of an invalid claim.
// FIXME: remove this connector once the stake chain is integrated.
use bitcoin::{
    psbt::Input,
    taproot::{self, ControlBlock, LeafVersion, TaprootSpendInfo},
    Address, Network, ScriptBuf, TapNodeHash, TapSighashType,
};
use secp256k1::XOnlyPublicKey;
use strata_bridge_primitives::{params::prelude::PAYOUT_OPTIMISTIC_TIMELOCK, scripts::prelude::*};

/// Possible spend paths for the connector C1.
///
/// The witness may not be known (hence, `()`) in use cases where the input index or sighash type
/// needs to be retrieved corresponding to the leaf whereas the witness ([`taproot::Signature`])
/// must be known when a path is used when spending the output.
#[derive(Debug, Clone, Copy)]
pub enum ConnectorC1Path<Witness = ()> {
    /// The script used for optimistic payouts.
    PayoutOptimistic(Witness),

    /// The script used for challenging the operator.
    Challenge(Witness),
}

impl<Witness: Sized> ConnectorC1Path<Witness> {
    /// Returns the input index for the leaf.
    ///
    /// The `PayoutOptimistic` leaf is spent in the third input of the `PayoutOptimistic`
    /// transaction, whereas the `Challenge` leaf is spent in the first input of the `Challenge`
    /// transaction.
    pub fn get_input_index(&self) -> u32 {
        match self {
            ConnectorC1Path::PayoutOptimistic(_) => 2,
            ConnectorC1Path::Challenge(_) => 0,
        }
    }

    /// Returns the sighash type for each of the connector leaves.
    pub fn get_sighash_type(&self) -> TapSighashType {
        match self {
            ConnectorC1Path::PayoutOptimistic(_) => TapSighashType::Default,
            ConnectorC1Path::Challenge(_) => TapSighashType::SinglePlusAnyoneCanPay,
        }
    }

    /// Adds a new witness to the leaf thereby creating a new leaf.
    pub fn add_witness_data<NewWitness: Sized>(
        self,
        witness_data: NewWitness,
    ) -> ConnectorC1Path<NewWitness> {
        match self {
            ConnectorC1Path::PayoutOptimistic(_) => ConnectorC1Path::PayoutOptimistic(witness_data),
            ConnectorC1Path::Challenge(_) => ConnectorC1Path::Challenge(witness_data),
        }
    }

    /// Returns the witness data for the leaf.
    pub fn get_witness_data(&self) -> &Witness {
        match self {
            ConnectorC1Path::PayoutOptimistic(witness_data) => witness_data,
            ConnectorC1Path::Challenge(witness_data) => witness_data,
        }
    }
}

/// Connector output from the Claim transaction that is used for challenging.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorC1 {
    n_of_n_agg_pubkey: XOnlyPublicKey,
    network: Network,
}

impl ConnectorC1 {
    /// Constructs a new instance of this connector.
    pub fn new(n_of_n_agg_pubkey: XOnlyPublicKey, network: Network) -> Self {
        Self {
            n_of_n_agg_pubkey,
            network,
        }
    }

    fn generate_payout_script(&self) -> ScriptBuf {
        n_of_n_with_timelock(&self.n_of_n_agg_pubkey, PAYOUT_OPTIMISTIC_TIMELOCK).compile()
    }

    /// Constructs the taproot address for this connector along with the spending info.
    pub fn generate_taproot_address(&self) -> (Address, TaprootSpendInfo) {
        let scripts: &[ScriptBuf] = &[self.generate_payout_script()];

        create_taproot_addr(
            &self.network,
            SpendPath::Both {
                internal_key: self.n_of_n_agg_pubkey,
                scripts,
            },
        )
        .expect("must be able to create taproot address")
    }

    /// Generates the locking script for this connector.
    pub fn generate_locking_script(&self) -> ScriptBuf {
        let (address, _) = self.generate_taproot_address();

        address.script_pubkey()
    }

    /// Generates the spend info for the payout optimistic path.
    pub fn generate_spend_info(&self) -> (ScriptBuf, ControlBlock) {
        let (_, taproot_spend_info) = self.generate_taproot_address();

        let script = self.generate_payout_script();
        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("payout optimistic script is always present in the address");

        (script, control_block)
    }

    /// Generates the merkle root for this connector.
    ///
    /// This can be used to tweak the public/private keys used for spending.
    pub fn generate_merkle_root(&self) -> TapNodeHash {
        let script = self.generate_payout_script();

        TapNodeHash::from_script(&script, LeafVersion::TapScript)
    }

    /// Finalizes the psbt input that spends this connector.
    ///
    /// This requires that the connector leaf contain the schnorr signature as the witness.
    pub fn finalize_input(&self, input: &mut Input, tapleaf: ConnectorC1Path<taproot::Signature>) {
        let witnesses = {
            match tapleaf {
                ConnectorC1Path::PayoutOptimistic(n_of_n_sig) => {
                    let (script, control_block) = self.generate_spend_info();
                    vec![
                        n_of_n_sig.serialize().to_vec(),
                        script.to_bytes(),
                        control_block.serialize(),
                    ]
                }
                ConnectorC1Path::Challenge(n_of_n_sig) => vec![n_of_n_sig.serialize().to_vec()],
            }
        };

        finalize_input(input, witnesses);
    }
}
