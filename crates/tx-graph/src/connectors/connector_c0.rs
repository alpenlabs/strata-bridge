use bitcoin::{
    psbt::Input,
    taproot::{ControlBlock, LeafVersion, TaprootSpendInfo},
    Address, Network, ScriptBuf, XOnlyPublicKey,
};
use secp256k1::schnorr::Signature;
use strata_bridge_primitives::scripts::prelude::*;

use super::params::{PAYOUT_OPTIMISTIC_TIMELOCK, SUPERBLOCK_MEASUREMENT_PERIOD};

#[derive(Debug, Clone, Copy)]
pub struct ConnectorC0 {
    n_of_n_agg_pubkey: XOnlyPublicKey,
    network: Network,
}

#[derive(Debug, Clone)]
pub enum ConnectorC0Leaf {
    PayoutOptimistic,
    Assert,
    InvalidateTs, // this needs WOTS data
}

impl ConnectorC0 {
    pub fn new(n_of_n_agg_pubkey: XOnlyPublicKey, network: Network) -> Self {
        Self {
            n_of_n_agg_pubkey,
            network,
        }
    }

    pub fn generate_tapleaf(&self, tapleaf: ConnectorC0Leaf) -> ScriptBuf {
        match tapleaf {
            ConnectorC0Leaf::PayoutOptimistic => {
                n_of_n_with_timelock(&self.n_of_n_agg_pubkey, PAYOUT_OPTIMISTIC_TIMELOCK)
            }
            ConnectorC0Leaf::Assert => n_of_n_script(&self.n_of_n_agg_pubkey), /* FIXME: use
                                                                                 * timelock */
            ConnectorC0Leaf::InvalidateTs => {
                n_of_n_with_timelock(&self.n_of_n_agg_pubkey, SUPERBLOCK_MEASUREMENT_PERIOD)
            }
        }
    }

    pub fn generate_locking_script(&self) -> ScriptBuf {
        let (address, _) = self.generate_taproot_address();

        address.script_pubkey()
    }

    pub fn generate_spend_info(&self, tapleaf: ConnectorC0Leaf) -> (ScriptBuf, ControlBlock) {
        let (_, taproot_spend_info) = self.generate_taproot_address();

        let script = self.generate_tapleaf(tapleaf);
        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script is always present in the address");

        (script, control_block)
    }

    fn generate_taproot_address(&self) -> (Address, TaprootSpendInfo) {
        let scripts = &[
            self.generate_tapleaf(ConnectorC0Leaf::PayoutOptimistic),
            self.generate_tapleaf(ConnectorC0Leaf::Assert),
            self.generate_tapleaf(ConnectorC0Leaf::InvalidateTs),
        ];

        create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
            .expect("should be able to create taproot address")
    }

    pub fn finalize_input_with_n_of_n(
        &self,
        input: &mut Input,
        n_of_n_signature: Signature,
        tapleaf: ConnectorC0Leaf,
    ) {
        if let ConnectorC0Leaf::InvalidateTs = tapleaf {
            // do nothing since this does not take an n_of_n sig
            return;
        }

        let (script, control_block) = self.generate_spend_info(tapleaf);

        finalize_input(
            input,
            [
                n_of_n_signature.serialize().to_vec(),
                script.to_bytes(),
                control_block.serialize(),
            ],
        );
    }
}
