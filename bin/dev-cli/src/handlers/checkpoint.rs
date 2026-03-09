use anyhow::{Context, Result};
use bitcoin::{
    hashes::Hash,
    locktime::absolute::LockTime,
    opcodes::{
        all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
        OP_FALSE,
    },
    script::Builder as ScriptBuilder,
    secp256k1::{Keypair, Secp256k1, XOnlyPublicKey},
    sighash::{Prevouts, SighashCache},
    taproot::{LeafVersion, TaprootBuilder},
    transaction::Version,
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn,
    TxOut, Witness,
};
use strata_identifiers::OLBlockId;
use strata_identifiers::Buf64;
use bitcoincore_rpc::{Client, RpcApi};
use secp256k1::rand::rngs::OsRng;
use strata_checkpoint_types_ssz::{
    compute_asm_manifests_hash, CheckpointClaim, CheckpointPayload, CheckpointSidecar,
    CheckpointTip, L2BlockRange, SignedCheckpointPayload,
};
use k256::{
    ecdsa::signature::SignatureEncoding,
    schnorr::{signature::Signer, SigningKey},
};
use rand::{thread_rng, Rng};
use tracing::info;
use strata_crypto::hash;
use ssz::Encode;
use strata_identifiers::OLBlockCommitment;
use strata_test_utils::ArbitraryGenerator;

use crate::cli::CreateAndPublishMockCheckpointArgs;

pub(crate) struct CheckpointTestHarness {
    genesis_l1_height: u32,
    sequencer_predicate: SigningKey,
    checkpoint_predicate: SigningKey,
    verified_tip: CheckpointTip,
}

impl CheckpointTestHarness {
    /// Creates a test harness with a specific genesis L1 height.
    ///
    /// Useful when the genesis height must align with an external test
    /// environment (e.g. Bitcoin regtest height in integration tests).
    pub(crate) fn new_with_genesis_height(genesis_l1_height: u32) -> Self {
        let mut rng = thread_rng();

        let genesis_ol_blkid = ArbitraryGenerator::new().generate();
        let genesis_blk = OLBlockCommitment::new(0, genesis_ol_blkid);

        let sequencer_predicate = SigningKey::random(&mut rng);
        let checkpoint_predicate = SigningKey::random(&mut rng);

        let genesis_tip = CheckpointTip::new(0, genesis_l1_height, genesis_blk);
        Self {
            genesis_l1_height,
            sequencer_predicate,
            checkpoint_predicate,
            verified_tip: genesis_tip,
        }
    }

    /// Generates a valid checkpoint payload signed by the checkpoint predicate.
    ///
    /// Creates a complete checkpoint payload including:
    /// - Random state diff and empty OL logs in the sidecar
    /// - Properly constructed checkpoint claim with manifest hashes
    /// - Valid checkpoint proof signature
    pub(crate) fn build_payload_with_tip(&self, new_tip: CheckpointTip) -> CheckpointPayload {
        let state_diff: Vec<u8> = ArbitraryGenerator::new().generate();
        let ol_logs = Vec::new();
        let sidecar = CheckpointSidecar::new(state_diff.clone(), ol_logs.clone()).unwrap();

        let state_diff_hash = hash::raw(&state_diff).into();
        let ol_logs_hash = hash::raw(&ol_logs.as_ssz_bytes()).into();

        let asm_manifests_hash = compute_asm_manifests_hash(Default::default());

        let l2_range = L2BlockRange::new(self.verified_tip.l2_commitment, new_tip.l2_commitment);
        let claim = CheckpointClaim::new(
            new_tip.epoch,
            l2_range,
            asm_manifests_hash,
            state_diff_hash,
            ol_logs_hash,
        );

        let proof = self
            .checkpoint_predicate
            .sign(&claim.as_ssz_bytes())
            .to_vec();

        CheckpointPayload::new(new_tip, sidecar, proof).unwrap()
    }

    /// Generates a new checkpoint tip that advances from the current verified tip.
    pub(crate) fn gen_new_tip(&self) -> CheckpointTip {
        let l1_blocks_processed: u32 = 0;
        let ol_blocks_processed: u64 = 1;
        self.gen_new_tip_with_advances(l1_blocks_processed, ol_blocks_processed)
    }

    /// Generates a new checkpoint tip with specific L1 and L2 advancement.
    ///
    /// Useful in integration tests where L1 block count is constrained
    /// by the regtest environment.
    pub(crate) fn gen_new_tip_with_advances(
        &self,
        l1_blocks: u32,
        ol_blocks: u64,
    ) -> CheckpointTip {
        let mut arb = ArbitraryGenerator::new();
        let verified_tip = self.verified_tip;

        let new_epoch = verified_tip.epoch + 1;
        let new_covered_l1_height = verified_tip.l1_height + l1_blocks;
        let new_ol_slot = verified_tip.l2_commitment().slot() + ol_blocks;
        let new_ol_blkid: OLBlockId = arb.generate();
        let new_ol_block_commitment = OLBlockCommitment::new(new_ol_slot, new_ol_blkid);

        CheckpointTip::new(new_epoch, new_covered_l1_height, new_ol_block_commitment)
    }

    /// Signs a checkpoint payload with the sequencer predicate key.
    ///
    /// The sequencer signature covers the entire SSZ-encoded checkpoint payload,
    /// attesting to the validity of the checkpoint transition.
    pub(crate) fn sign_payload(&self, payload: CheckpointPayload) -> SignedCheckpointPayload {
        let signature = self
            .sequencer_predicate
            .sign(&payload.as_ssz_bytes())
            .to_vec();
        let mut sig = [0u8; 64];
        sig.copy_from_slice(&signature[..64]);
        SignedCheckpointPayload::new(payload, Buf64::from(sig))
    }
}


pub(crate) async fn handle_create_and_publish_mock_checkpoint(
    _args: CreateAndPublishMockCheckpointArgs,
) -> Result<()> {
    let cp_helper = CheckpointTestHarness::new_with_genesis_height(101);
    let new_tip = cp_helper.gen_new_tip();
    let payload = cp_helper.build_payload_with_tip(new_tip);
    let signed_payload = cp_helper.sign_payload(payload);

    Ok(())

}

fn get_new_tip()->CheckpointTip{
    let new_ol_block_commitment = OLBlockCommitment::new(1, Default::default());
    CheckpointTip::new(1, 101, new_ol_block_commitment)
}


/// Build a reveal script that embeds payload data in a taproot script leaf.
///
/// Format: `<internal_key> OP_CHECKSIG OP_FALSE OP_IF <payload_chunks> OP_ENDIF`
fn build_reveal_script(internal_key: &XOnlyPublicKey, payload: &[u8]) -> ScriptBuf {
    let mut builder = ScriptBuilder::new()
        .push_x_only_key(internal_key)
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF);

    // Push payload in chunks (max 520 bytes per push)
    for chunk in payload.chunks(520) {
        builder = builder.push_slice::<&bitcoin::script::PushBytes>(
            chunk.try_into().expect("chunk must be <= 520 bytes"),
        );
    }

    builder.push_opcode(OP_ENDIF).into_script()
}

/// Build and broadcast a taproot envelope transaction embedding arbitrary payload.
///
/// Uses a commit-reveal pattern:
/// 1. Commit: sends funds to a taproot address with the payload in a script leaf.
/// 2. Reveal: spends via script path, exposing the payload in the witness.
///
/// Returns the reveal transaction's txid.
pub(crate) fn build_and_broadcast_envelope_tx(
    client: &Client,
    payload: Vec<u8>,
) -> Result<bitcoin::Txid> {
    let secp = Secp256k1::new();

    // Generate ephemeral keypair
    let keypair = Keypair::new(&secp, &mut OsRng);
    let (internal_key, _) = XOnlyPublicKey::from_keypair(&keypair);

    // Build reveal script with embedded payload
    let reveal_script = build_reveal_script(&internal_key, &payload);

    // Build taproot with the reveal script as a leaf
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .context("failed to add reveal script leaf")?
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow::anyhow!("failed to finalize taproot: {:?}", e))?;

    let taproot_address = Address::p2tr(
        &secp,
        internal_key,
        taproot_spend_info.merkle_root(),
        Network::Regtest,
    );

    // === Commit: fund the taproot address ===
    let fee = Amount::from_sat(2_000);
    let dust = Amount::from_sat(1_000);
    let funding_amount = fee + dust;

    let commit_txid = client
        .send_to_address(
            &taproot_address,
            funding_amount,
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .context("failed to fund taproot address")?;

    info!(event = "commit tx broadcast", %commit_txid);

    // Find the vout in the commit tx
    let commit_tx = client
        .get_raw_transaction(&commit_txid, None)
        .context("failed to get commit tx")?;

    let commit_vout = commit_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == taproot_address.script_pubkey())
        .context("commit output not found")? as u32;

    // === Reveal: spend via script path ===
    let control_block = taproot_spend_info
        .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
        .context("failed to create control block")?;

    let change_address = client
        .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))
        .context("failed to get change address")?
        .assume_checked();

    let change_output = TxOut {
        value: funding_amount - fee,
        script_pubkey: change_address.script_pubkey(),
    };

    // Build unsigned reveal tx
    let tx_input = TxIn {
        previous_output: OutPoint::new(commit_txid, commit_vout),
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };

    let mut reveal_tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![tx_input],
        output: vec![change_output],
    };

    // Sign the reveal transaction (script-path spend)
    let prevouts = vec![commit_tx.output[commit_vout as usize].clone()];
    let mut sighash_cache = SighashCache::new(&reveal_tx);
    let leaf_hash =
        bitcoin::taproot::TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&prevouts),
            leaf_hash,
            TapSighashType::Default,
        )
        .context("failed to compute sighash")?;

    let msg = bitcoin::secp256k1::Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_schnorr(&msg, &keypair);

    let mut witness = Witness::new();
    witness.push(sig.as_ref());
    witness.push(reveal_script.as_bytes());
    witness.push(control_block.serialize());
    reveal_tx.input[0].witness = witness;

    // Broadcast reveal tx
    let reveal_txid = client
        .send_raw_transaction(&reveal_tx)
        .context("failed to broadcast reveal tx")?;

    info!(event = "reveal tx broadcast", %reveal_txid);

    Ok(reveal_txid)
}

#[cfg(test)]
mod tests {
    use bitcoincore_rpc::Auth;

    use super::*;

    /// Integration test: requires a running regtest bitcoind at localhost:18443
    /// with wallet "default" loaded and funded.
    ///
    /// Run: `cargo test -p dev-cli -- --ignored test_envelope_tx_accepted`
    #[test]
    #[ignore = "requires running regtest bitcoind"]
    fn test_envelope_tx_accepted() {
        let client = Client::new(
            "http://localhost:18443/wallet/default",
            Auth::UserPass("rpcuser".into(), "rpcpassword".into()),
        )
        .expect("failed to create rpc client");

        // Make sure we have funds
        let address = client
            .get_new_address(None, Some(bitcoincore_rpc::json::AddressType::Bech32m))
            .expect("failed to get address")
            .assume_checked();
        client
            .generate_to_address(110, &address)
            .expect("failed to mine blocks");

        let payload = b"hello checkpoint".to_vec();
        let txid =
            build_and_broadcast_envelope_tx(&client, payload).expect("envelope tx should succeed");

        // Confirm the tx is in the mempool
        let mempool = client.get_raw_mempool().expect("failed to get mempool");
        assert!(
            mempool.contains(&txid),
            "reveal tx {txid} should be in the mempool"
        );

        // Mine it and verify it's confirmed
        client
            .generate_to_address(1, &address)
            .expect("failed to mine block");

        let tx_info = client
            .get_raw_transaction_info(&txid, None)
            .expect("failed to get tx info");
        assert!(
            tx_info.confirmations.unwrap_or(0) > 0,
            "reveal tx should be confirmed"
        );
    }
}
