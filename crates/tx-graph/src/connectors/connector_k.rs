use std::sync::Arc;

use bitcoin::{
    hashes::Hash,
    psbt::Input,
    taproot::{ControlBlock, LeafVersion},
    Address, Network, ScriptBuf, Txid,
};
use bitvm::{
    signatures::wots::{wots256, wots32},
    treepp::*,
};
use secp256k1::XOnlyPublicKey;
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{scripts::prelude::*, types::OperatorIdx, wots};
use tracing::trace;

#[derive(Debug, Clone)]
pub struct ConnectorK<Db: PublicDb> {
    pub n_of_n_agg_pubkey: XOnlyPublicKey,

    pub network: Network,

    pub operator_idx: OperatorIdx,

    pub db: Arc<Db>,
}

impl<Db: PublicDb> ConnectorK<Db> {
    pub fn new(
        n_of_n_agg_pubkey: XOnlyPublicKey,
        network: Network,
        operator_idx: OperatorIdx,
        db: Arc<Db>,
    ) -> Self {
        Self {
            n_of_n_agg_pubkey,
            operator_idx,
            network,
            db,
        }
    }

    async fn create_locking_script(&self, deposit_txid: Txid) -> ScriptBuf {
        let wots::PublicKeys {
            bridge_out_txid: bridge_out_txid_public_key,
            superblock_hash: _,
            superblock_period_start_ts: superblock_period_start_ts_public_key,
            groth16: _,
        } = self
            .db
            .get_wots_public_keys(self.operator_idx, deposit_txid)
            .await
            .unwrap()
            .unwrap(); // FIXME: Handle me

        script! {
            // superblock_period_start_timestamp
            { wots32::checksig_verify(superblock_period_start_ts_public_key.0, true) }
            // ts_from_nibbles OP_CLTV OP_DROP // check absolute locktime


            // bridge_out_tx_id
            { wots256::checksig_verify(bridge_out_txid_public_key.0, true) }

            OP_TRUE
        }
        .compile()
    }

    pub async fn create_taproot_address(&self, deposit_txid: Txid) -> Address {
        let scripts = &[self.create_locking_script(deposit_txid).await];

        let (taproot_address, _) =
            create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts })
                .expect("should be able to add scripts");

        taproot_address
    }

    pub async fn generate_spend_info(&self, deposit_txid: Txid) -> (ScriptBuf, ControlBlock) {
        let script = self.create_locking_script(deposit_txid).await;

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

    // NOTE: this fn cannot be made async because `bitvm::ExecuteInfo` is neither `Sync` nor `Send`.
    #[expect(clippy::too_many_arguments)]
    pub fn create_tx_input(
        &self,
        input: &mut Input,
        msk: &str,
        bridge_out_txid: Txid, // starts with 0x0..
        superblock_period_start_ts: u32,
        deposit_txid: Txid,
        script: ScriptBuf,
        control_block: ControlBlock,
    ) {
        let deposit_msk = get_deposit_master_secret_key(msk, deposit_txid);

        let witness = script! {
            { wots256::sign(&secret_key_for_bridge_out_txid(&deposit_msk), &bridge_out_txid.to_byte_array()) }

            { wots32::sign(&secret_key_for_superblock_period_start_ts(&deposit_msk), &superblock_period_start_ts.to_le_bytes()) }
        };

        let result = execute_script(witness.clone());
        let mut witness_stack = (0..result.final_stack.len())
            .map(|index| result.final_stack.get(index))
            .collect::<Vec<_>>();

        trace!(event = "created witness sig", ?witness_stack);

        trace!(kind = "kickoff-claim connector witness", ?witness);

        trace!(kind = "kickoff-claim connector script", ?script);

        witness_stack.push(script.to_bytes());
        witness_stack.push(control_block.serialize());

        finalize_input(input, witness_stack);
    }
}
