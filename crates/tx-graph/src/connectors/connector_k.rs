use bitcoin::{
    hashes::Hash,
    psbt::Input,
    taproot::{ControlBlock, LeafVersion},
    Address, Network, ScriptBuf, Txid,
};
use bitvm::{signatures::wots::wots256, treepp::*};
use secp256k1::XOnlyPublicKey;
use strata_bridge_primitives::{scripts::prelude::*, wots};

/// Connector between the Kickoff and Claim transactions.
///
/// # NOTE: This will be replaced by the stake chain connector.
#[derive(Debug, Clone, Copy)]
pub struct ConnectorK {
    /// The n-of-n aggregate public key.
    pub n_of_n_agg_pubkey: XOnlyPublicKey,

    /// The bitcoin network for the addresses generated by the connector.
    pub network: Network,

    /// The WOTS public key used for bitcommitment scripts.
    pub wots_public_key: wots::Wots256PublicKey,
}

impl ConnectorK {
    /// Constructs a new connector.
    pub fn new(
        n_of_n_agg_pubkey: XOnlyPublicKey,
        network: Network,
        withdrawal_fulfillment_pk: wots::Wots256PublicKey,
    ) -> Self {
        Self {
            n_of_n_agg_pubkey,
            network,
            wots_public_key: withdrawal_fulfillment_pk,
        }
    }

    fn create_locking_script(&self) -> ScriptBuf {
        let wots::Wots256PublicKey(withdrawal_fulfillment_pk) = self.wots_public_key;

        script! {
            // bridge_out_tx_id
            { wots256::checksig_verify(withdrawal_fulfillment_pk, true) }

            OP_TRUE
        }
        .compile()
    }

    /// Creates a taproot address for the connector corresponding to the locking script.
    pub fn create_taproot_address(&self) -> Address {
        let scripts = &[self.create_locking_script()];

        let (taproot_address, _) =
            create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
                .expect("should be able to add scripts");

        taproot_address
    }

    /// Generates the taproot spend info for the connector.
    pub fn generate_spend_info(&self) -> (ScriptBuf, ControlBlock) {
        let script = self.create_locking_script();

        let (_, spend_info) = create_taproot_addr(
            &self.network,
            SpendPath::ScriptSpend {
                scripts: &[script.clone()],
            },
        )
        .expect("should be able to create taproot address");

        let control_block = spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script must be part of the address");

        (script, control_block)
    }

    /// Finalizes the input to the transaction that spends this connector.
    pub fn create_tx_input(
        &self,
        input: &mut Input,
        msk: &str,
        withdrawal_fulfillment_txid: Txid,
        deposit_txid: Txid,
        script: ScriptBuf,
        control_block: ControlBlock,
    ) {
        let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);

        let witness = script! {
            { wots256::sign(&secret_key_for_bridge_out_txid(&deposit_msk), &withdrawal_fulfillment_txid.to_byte_array()) }
        };

        let result = execute_script(witness.clone());
        let mut witness_stack = (0..result.final_stack.len())
            .map(|index| result.final_stack.get(index))
            .collect::<Vec<_>>();

        witness_stack.push(script.to_bytes());
        witness_stack.push(control_block.serialize());

        finalize_input(input, witness_stack);
    }
}
