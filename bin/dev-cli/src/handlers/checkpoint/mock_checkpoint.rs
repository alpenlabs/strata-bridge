use alpen_bridge_params::default::BRIDGE_DENOMINATION;
use k256::{
    ecdsa::signature::SignatureEncoding,
    schnorr::{signature::Signer, SigningKey},
};
use rand::{thread_rng, Rng};
use ssz::Encode;
use strata_checkpoint_types_ssz::{
    compute_asm_manifests_hash, CheckpointClaim, CheckpointPayload, CheckpointSidecar,
    CheckpointTip, L2BlockRange, OLLog, SignedCheckpointPayload, TerminalHeaderComplement,
};
use strata_crypto::hash;
use strata_identifiers::{strata_codec::encode_to_vec, Buf32, Buf64, OLBlockCommitment, OLBlockId};
use strata_ol_chain_types_new::SimpleWithdrawalIntentLogData;
use strata_primitives::bitcoin_bosd::Descriptor;
use strata_test_utils::ArbitraryGenerator;

use super::constants::{BRIDGE_GATEWAY_ACCT_SERIAL, MOCK_PREDICATE_KEY};

/// Builds mock signed checkpoint payloads for testing.
///
/// TODO: MdTeach: update `verified_tip` after each build to support multi-epoch sequences.
pub(crate) struct MockCheckpointBuilder {
    sequencer_predicate: SigningKey,
    checkpoint_predicate: SigningKey,
    verified_tip: CheckpointTip,
}

impl MockCheckpointBuilder {
    /// Creates mock checkpoint builder with the given genesis L1 height.
    pub(crate) fn new(genesis_l1_height: u32) -> Self {
        let genesis_ol_blkid = OLBlockId::from(Buf32::zero());
        let genesis_ol_blidx = 0;
        let genesis_blk = OLBlockCommitment::new(genesis_ol_blidx, genesis_ol_blkid);

        // For testing we use ASM on `AlwaysAccept` predicate which accepts any valid schnorr
        // signature
        let sk = SigningKey::from_bytes(&MOCK_PREDICATE_KEY).expect("invalid mock predicate key");

        let genesis_tip = CheckpointTip::new(0, genesis_l1_height, genesis_blk);
        Self {
            sequencer_predicate: sk.clone(),
            checkpoint_predicate: sk,
            verified_tip: genesis_tip,
        }
    }

    /// Generates a mock checkpoint payload signed by the checkpoint predicate.
    pub(crate) fn build_payload_with_tip(
        &self,
        new_tip: CheckpointTip,
        num_withdrawals: usize,
    ) -> CheckpointPayload {
        let mut arb = ArbitraryGenerator::new();
        let state_diff: Vec<u8> = arb.generate();

        let terminal_header_complement = TerminalHeaderComplement::new(
            thread_rng().gen(),
            arb.generate(),
            arb.generate(),
            arb.generate(),
        );
        let terminal_header_complement_hash = terminal_header_complement.compute_hash();

        let dest = Descriptor::new_p2wpkh(&[0u8; 20]);
        let ol_logs: Vec<OLLog> = (0..num_withdrawals)
            .map(|_| {
                let log_data = SimpleWithdrawalIntentLogData::new(
                    BRIDGE_DENOMINATION.to_sat(),
                    dest.to_bytes(),
                    Default::default(),
                )
                .unwrap();

                OLLog::new(
                    BRIDGE_GATEWAY_ACCT_SERIAL,
                    encode_to_vec(&log_data).unwrap(),
                )
            })
            .collect();

        let state_diff_hash = hash::raw(&state_diff).into();
        let ol_logs_hash = hash::raw(&ol_logs.as_ssz_bytes()).into();

        let sidecar =
            CheckpointSidecar::new(state_diff, ol_logs, terminal_header_complement).unwrap();

        let asm_manifests_hash = compute_asm_manifests_hash(Default::default());

        let l2_range = L2BlockRange::new(self.verified_tip.l2_commitment, new_tip.l2_commitment);
        let claim = CheckpointClaim::new(
            new_tip.epoch,
            l2_range,
            asm_manifests_hash,
            state_diff_hash,
            ol_logs_hash,
            terminal_header_complement_hash,
        );

        let proof = self
            .checkpoint_predicate
            .sign(&claim.as_ssz_bytes())
            .to_vec();

        CheckpointPayload::new(new_tip, sidecar, proof).unwrap()
    }

    /// Generates a new checkpoint tip that advances from the current verified tip.
    pub(crate) fn gen_new_tip(&self, l1_blocks: u32, ol_blocks: u64) -> CheckpointTip {
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
