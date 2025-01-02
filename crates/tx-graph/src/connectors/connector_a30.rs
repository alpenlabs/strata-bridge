use std::sync::Arc;

use bitcoin::{
    psbt::Input,
    taproot::{ControlBlock, LeafVersion, Signature, TaprootSpendInfo},
    Address, Network, ScriptBuf, TapSighashType, Txid, XOnlyPublicKey,
};
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{scripts::prelude::*, types::OperatorIdx};

use super::params::PAYOUT_TIMELOCK;

#[derive(Debug, Clone)]
pub struct ConnectorA30<Db: PublicDb> {
    n_of_n_agg_pubkey: XOnlyPublicKey,

    network: Network,

    db: Arc<Db>,
}

#[derive(Debug, Clone, Copy)]
pub enum ConnectorA30Leaf {
    Payout,
    Disprove,
}

impl<Db: PublicDb> ConnectorA30<Db> {
    pub fn new(n_of_n_agg_pubkey: XOnlyPublicKey, network: Network, db: Arc<Db>) -> Self {
        Self {
            n_of_n_agg_pubkey,
            network,
            db,
        }
    }

    pub fn generate_tapleaf(&self, tapleaf: ConnectorA30Leaf) -> ScriptBuf {
        match tapleaf {
            ConnectorA30Leaf::Payout => {
                n_of_n_with_timelock(&self.n_of_n_agg_pubkey, PAYOUT_TIMELOCK)
            }
            ConnectorA30Leaf::Disprove => n_of_n_script(&self.n_of_n_agg_pubkey),
        }
    }

    pub fn generate_locking_script(&self) -> ScriptBuf {
        let (address, _) = self.generate_taproot_address();

        address.script_pubkey()
    }

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

    pub async fn finalize_input(
        &self,
        input: &mut Input,
        operator_idx: OperatorIdx,
        payout_txid: Txid,
        tapleaf: ConnectorA30Leaf,
    ) {
        let (script, control_block) = self.generate_spend_info(tapleaf);

        let input_index = match tapleaf {
            ConnectorA30Leaf::Payout => 1,
            ConnectorA30Leaf::Disprove => 0,
        };

        let n_of_n_sig = self
            .db
            .get_signature(operator_idx, payout_txid, input_index)
            .await
            .unwrap()
            .unwrap(); // FIXME: handle me

        let sighash_type = match tapleaf {
            ConnectorA30Leaf::Payout => TapSighashType::Default,
            ConnectorA30Leaf::Disprove => TapSighashType::Single,
        };

        let signature = Signature {
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
