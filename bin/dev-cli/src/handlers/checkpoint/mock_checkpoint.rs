use anyhow::Result;
use k256::{
    ecdsa::signature::SignatureEncoding,
    schnorr::{signature::Signer, SigningKey},
};
use rand::thread_rng;
use ssz::Encode;
use strata_checkpoint_types_ssz::{
    compute_asm_manifests_hash, CheckpointClaim, CheckpointPayload, CheckpointSidecar,
    CheckpointTip, L2BlockRange, SignedCheckpointPayload,
};
use strata_crypto::hash;
use strata_identifiers::{Buf64, OLBlockCommitment, OLBlockId};
use strata_test_utils::ArbitraryGenerator;

use crate::cli::CreateAndPublishMockCheckpointArgs;

pub(crate) struct CheckpointTestHarness {
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

        let state_diff_hash = hash::raw(&state_diff).into();
        let ol_logs_hash = hash::raw(&ol_logs.as_ssz_bytes()).into();

        let sidecar = CheckpointSidecar::new(state_diff, ol_logs).unwrap();

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
        self.gen_new_tip_with_advances(0, 1)
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
    let _signed_payload = cp_helper.sign_payload(payload);

    Ok(())
}
