use bitcoin::{
    psbt::Input,
    taproot::{self, ControlBlock, LeafVersion, TaprootSpendInfo},
    Address, Network, ScriptBuf, TapSighashType, XOnlyPublicKey,
};
use secp256k1::schnorr;
use strata_bridge_primitives::{params::connectors::PAYOUT_TIMELOCK, scripts::prelude::*};

/// Connector from the PostAssert transaction.
///
/// This connector is spent either by the Payout transaction to recover the stake or by the Disprove
/// transaction to slash the stake.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorA30 {
    n_of_n_agg_pubkey: XOnlyPublicKey,

    network: Network,
}

/// Possible spending paths for the [`ConnectorA30`].
#[derive(Debug, Clone, Copy)]
pub enum ConnectorA30Leaf {
    Payout,
    Disprove,
}

impl ConnectorA30Leaf {}

impl ConnectorA30Leaf {
    /// Generates the locking script for this leaf.
    pub fn generate_locking_script(&self, n_of_n_agg_pubkey: &XOnlyPublicKey) -> ScriptBuf {
        match self {
            ConnectorA30Leaf::Payout => n_of_n_with_timelock(n_of_n_agg_pubkey, PAYOUT_TIMELOCK),
            ConnectorA30Leaf::Disprove => n_of_n_script(n_of_n_agg_pubkey),
        }
    }

    /// Returns the input index for the leaf.
    ///
    /// The `Payout` leaf is spent in the second input of the `Payout` transaction,
    /// whereas the `Disprove` leaf is spent in the first input of the `Disprove` transaction.
    pub fn get_input_index(&self) -> u32 {
        match self {
            ConnectorA30Leaf::Payout => 1,
            ConnectorA30Leaf::Disprove => 0,
        }
    }

    /// Returns the sighash type for each of the connector leaves.
    pub fn get_sighash_type(&self) -> TapSighashType {
        match self {
            ConnectorA30Leaf::Payout => TapSighashType::Default,
            ConnectorA30Leaf::Disprove => TapSighashType::Single,
        }
    }
}

impl ConnectorA30 {
    /// Constructs a new instance of this connector.
    pub fn new(n_of_n_agg_pubkey: XOnlyPublicKey, network: Network) -> Self {
        Self {
            n_of_n_agg_pubkey,
            network,
        }
    }

    /// Creates the taproot script for the given tapleaf.
    pub fn generate_tapleaf(&self, tapleaf: ConnectorA30Leaf) -> ScriptBuf {
        tapleaf.generate_locking_script(&self.n_of_n_agg_pubkey)
    }

    /// Creates the locking script for this connector.
    pub fn generate_locking_script(&self) -> ScriptBuf {
        let (address, _) = self.generate_taproot_address();

        address.script_pubkey()
    }

    /// Creates the tapoot spend info for the given leaf.
    pub fn generate_spend_info(&self, tapleaf: ConnectorA30Leaf) -> (ScriptBuf, ControlBlock) {
        let (_, taproot_spend_info) = self.generate_taproot_address();

        let script = self.generate_tapleaf(tapleaf);
        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script is always present in the address");

        (script, control_block)
    }

    fn generate_taproot_address(&self) -> (Address, TaprootSpendInfo) {
        let scripts = &[
            self.generate_tapleaf(ConnectorA30Leaf::Payout),
            self.generate_tapleaf(ConnectorA30Leaf::Disprove),
        ];

        create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
            .expect("should be able to create taproot address")
    }

    /// Finalizes the input for the psbt that spends this connector.
    pub fn finalize_input(
        &self,
        input: &mut Input,
        tapleaf: ConnectorA30Leaf,
        n_of_n_sig: schnorr::Signature,
    ) {
        let (script, control_block) = self.generate_spend_info(tapleaf);

        let sighash_type = tapleaf.get_sighash_type();

        let signature = taproot::Signature {
            signature: n_of_n_sig,
            sighash_type,
        };

        finalize_input(
            input,
            [
                signature.serialize().to_vec(),
                script.to_bytes(),
                control_block.serialize(),
            ],
        );
    }
}
