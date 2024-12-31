use std::sync::Arc;

use bitcoin::{
    hashes::Hash,
    psbt::Input,
    taproot::{ControlBlock, LeafVersion, TaprootSpendInfo},
    Address, Network, ScriptBuf, Txid,
};
use bitvm::{
    bn254::chunk_superblock::H256,
    groth16::g16::{self, N_TAPLEAVES},
    hash::sha256::sha256,
    pseudo::NMUL,
    signatures::wots::{wots256, wots32, SignatureImpl},
    treepp::*,
};
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{
    params::prelude::*,
    scripts::{prelude::*, wots},
    types::OperatorIdx,
};
use tracing::trace;

use crate::partial_verification_scripts::PARTIAL_VERIFIER_SCRIPTS;

#[derive(Debug, Clone)]
pub struct ConnectorA31<DB: PublicDb> {
    network: Network,

    db: Arc<DB>,
}

#[derive(Debug, Clone)]
#[expect(clippy::large_enum_variant)]
pub enum ConnectorA31Leaf {
    DisproveProof((Script, Option<Script>)),
    DisproveSuperblockCommitment(Option<(wots256::Signature, wots32::Signature, [u8; 80])>),
    DisprovePublicInputsCommitment(
        Txid,
        Option<(
            wots256::Signature,
            wots256::Signature,
            wots32::Signature,
            wots256::Signature,
        )>,
    ),
}

impl ConnectorA31Leaf {
    pub fn generate_locking_script(self, public_keys: wots::PublicKeys) -> Script {
        let wots::PublicKeys {
            bridge_out_txid: bridge_out_txid_public_key,
            superblock_hash: superblock_hash_public_key,
            superblock_period_start_ts: superblock_period_start_ts_public_key,
            groth16: Groth16PublicKeys(([public_inputs_hash_public_key], _, _)),
        } = public_keys;
        match self {
            ConnectorA31Leaf::DisproveSuperblockCommitment(_) => {
                script! {
                    // committed superblock hash
                    { wots256::compact::checksig_verify(superblock_hash_public_key.0) }
                    { sb_hash_from_nibbles() } { H256::toaltstack() }

                    // committed superblock period start timestamp
                    { wots32::compact::checksig_verify(superblock_period_start_ts_public_key.0) }
                    { ts_from_nibbles() } OP_TOALTSTACK

                    // extract superblock timestamp from header
                    extract_superblock_ts_from_header

                    // assert: 0 < sbv.ts - sb_start_ts < superblock_period
                    OP_FROMALTSTACK
                    OP_SUB
                    OP_DUP
                    0 OP_GREATERTHAN OP_VERIFY
                    { SUPERBLOCK_PERIOD } OP_LESSTHAN OP_VERIFY

                    // sbv.hash()
                    { sha256(80) }
                    { sha256(32) }
                    { sb_hash_from_bytes() }

                    { H256::fromaltstack() }

                    // assert sb.hash < committed_sb_hash
                    { H256::lessthan(1, 0) } OP_VERIFY

                    OP_TRUE
                }
            }

            ConnectorA31Leaf::DisprovePublicInputsCommitment(deposit_txid, _) => {
                script! {
                    { wots256::compact::checksig_verify(superblock_hash_public_key.0) }
                    for _ in 0..32 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }

                    { wots256::compact::checksig_verify(bridge_out_txid_public_key.0) }
                    for _ in 0..32 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }

                    { wots32::compact::checksig_verify(superblock_period_start_ts_public_key.0) }
                    for _ in 0..4 { OP_SWAP { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK }

                    { wots256::compact::checksig_verify(public_inputs_hash_public_key) }
                    for _ in 0..32 { { NMUL(1 << 4) } OP_ADD OP_TOALTSTACK } // TODO: add OP_SWAP after fixing groth16 witnernitz issue


                    for _ in 0..32 { OP_FROMALTSTACK }
                    for _ in 0..4 { OP_FROMALTSTACK }
                    for _ in 0..32 { OP_FROMALTSTACK } // add_bincode_padding_bytes32
                    for _ in 0..32 { OP_FROMALTSTACK } // add_bincode_padding_bytes32


                    for &b in deposit_txid.to_byte_array().iter().rev() { { b } } // add_bincode_padding_bytes32

                    { sha256(3 * 32 + 4) }
                    hash_to_bn254_fq

                    // verify that hashes don't match
                    for i in (1..32).rev() {
                        {i + 1} OP_ROLL
                        OP_EQUAL OP_TOALTSTACK
                    }
                    OP_EQUAL
                    for _ in 1..32 { OP_FROMALTSTACK OP_BOOLAND }
                    OP_NOT
                }
            }
            ConnectorA31Leaf::DisproveProof((disprove_script, _)) => disprove_script,
        }
    }

    pub fn generate_witness_script(self) -> Script {
        match self {
            ConnectorA31Leaf::DisproveSuperblockCommitment(Some((
                sig_superblock_hash,
                sig_superblock_period_start_ts,
                raw_superblock_header_bytes,
            ))) => {
                script! {
                    { raw_superblock_header_bytes.to_vec() }
                    { sig_superblock_period_start_ts.to_compact_script() }
                    { sig_superblock_hash.to_compact_script() }
                }
            }
            ConnectorA31Leaf::DisprovePublicInputsCommitment(
                _,
                Some((
                    sig_superblock_hash,
                    sig_bridge_out_txid,
                    sig_superblock_period_start_ts,
                    sig_public_inputs_hash,
                )),
            ) => {
                script! {
                    { sig_public_inputs_hash.to_compact_script() }
                    { sig_superblock_period_start_ts.to_compact_script() }
                    { sig_bridge_out_txid.to_compact_script() }
                    { sig_superblock_hash.to_compact_script() }
                }
            }
            ConnectorA31Leaf::DisproveProof((_, Some(witness_script))) => witness_script,
            _ => panic!("no data provided to finalize input"),
        }
    }
}

impl<Db: PublicDb> ConnectorA31<Db> {
    pub fn new(network: Network, db: Arc<Db>) -> Self {
        Self { network, db }
    }

    pub async fn generate_tapleaf(
        &self,
        tapleaf: ConnectorA31Leaf,
        deposit_txid: Txid,
    ) -> ScriptBuf {
        let public_keys = self.db.get_wots_public_keys(0, deposit_txid).await.unwrap(); // FIXME: handle me
        tapleaf.generate_locking_script(public_keys).compile()
    }

    pub async fn generate_locking_script(
        &self,
        deposit_txid: Txid,
        operator_idx: OperatorIdx,
    ) -> ScriptBuf {
        let (address, _) = self
            .generate_taproot_address(deposit_txid, operator_idx)
            .await;

        address.script_pubkey()
    }

    pub async fn generate_spend_info(
        &self,
        tapleaf: ConnectorA31Leaf,
        deposit_txid: Txid,
        operator_idx: OperatorIdx,
    ) -> (ScriptBuf, ControlBlock) {
        let (_, taproot_spend_info) = self
            .generate_taproot_address(deposit_txid, operator_idx)
            .await;

        let script = self.generate_tapleaf(tapleaf, deposit_txid).await;
        let control_block = taproot_spend_info
            .control_block(&(script.clone(), LeafVersion::TapScript))
            .expect("script is always present in the address");

        (script, control_block)
    }

    pub async fn generate_disprove_scripts(
        &self,
        deposit_txid: Txid,
        operator_idx: OperatorIdx,
    ) -> [Script; N_TAPLEAVES] {
        let partial_disprove_scripts = &PARTIAL_VERIFIER_SCRIPTS;

        trace!(action = "getting public_keys from db", %operator_idx, %deposit_txid);
        let public_keys = self
            .db
            .get_wots_public_keys(operator_idx, deposit_txid)
            .await
            .unwrap() // FIXME: Handle me
            .groth16;

        trace!(action = "got public_keys from db", %operator_idx, %deposit_txid);

        trace!(action = "generating disprove scripts", %operator_idx);
        let disprove_scripts =
            g16::generate_disprove_scripts(public_keys.0, partial_disprove_scripts);
        trace!(action = "generated disprove scripts", %operator_idx, num_disprove_scripts=%disprove_scripts.len());

        disprove_scripts
    }

    async fn generate_taproot_address(
        &self,
        deposit_txid: Txid,
        operator_idx: OperatorIdx,
    ) -> (Address, TaprootSpendInfo) {
        trace!(action = "generating disprove chain and invalidate public data leaves", %operator_idx);
        let disprove_scripts = self
            .generate_disprove_scripts(deposit_txid, operator_idx)
            .await;

        let mut scripts = vec![
            self.generate_tapleaf(
                ConnectorA31Leaf::DisproveSuperblockCommitment(None),
                deposit_txid,
            )
            .await,
            self.generate_tapleaf(
                ConnectorA31Leaf::DisprovePublicInputsCommitment(deposit_txid, None),
                deposit_txid,
            )
            .await,
        ];
        trace!(event = "generated disprove chain and invalidate public data leaves", %operator_idx);

        trace!(action = "generating invalidate proof leaves", %N_TAPLEAVES, %operator_idx);

        let mut invalidate_proof_tapleaves = Vec::with_capacity(N_TAPLEAVES);
        for disprove_script in disprove_scripts.into_iter() {
            invalidate_proof_tapleaves.push(
                self.generate_tapleaf(
                    ConnectorA31Leaf::DisproveProof((disprove_script, None)),
                    deposit_txid,
                )
                .await,
            );
        }
        trace!(event = "generated invalidate proof leaves", %operator_idx);

        scripts.extend(invalidate_proof_tapleaves.into_iter());

        trace!(action = "creating taproot address", %operator_idx);
        create_taproot_addr(&self.network, SpendPath::ScriptSpend { scripts: &scripts })
            .expect("should be able to create taproot address")
    }

    pub async fn finalize_input(
        &self,
        input: &mut Input,
        tapleaf: ConnectorA31Leaf,
        deposit_txid: Txid,
        operator_idx: OperatorIdx,
    ) {
        let (script, control_block) = self
            .generate_spend_info(tapleaf.clone(), deposit_txid, operator_idx)
            .await;

        let witness_script = tapleaf.generate_witness_script();

        let mut witness_stack = taproot_witness_signatures(witness_script);

        witness_stack.push(script.to_bytes());
        witness_stack.push(control_block.serialize());

        finalize_input(input, witness_stack);
    }
}
