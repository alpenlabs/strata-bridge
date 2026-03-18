use k256::{
    ecdsa::signature::SignatureEncoding,
    schnorr::{signature::Signer, SigningKey},
};
use rand::{thread_rng, Rng};
use ssz::Encode;
use strata_bridge_primitives::constants::BRIDGE_DENOMINATION;
use strata_checkpoint_types_ssz::{
    compute_asm_manifests_hash, CheckpointClaim, CheckpointPayload, CheckpointSidecar,
    CheckpointTip, L2BlockRange, OLLog, SignedCheckpointPayload, TerminalHeaderComplement,
};
use strata_crypto::hash;
use strata_identifiers::{strata_codec::encode_to_vec, Buf32, Buf64, OLBlockCommitment, OLBlockId};
use strata_ol_chain_types_new::SimpleWithdrawalIntentLogData;
use strata_primitives::bitcoin_bosd::Descriptor;
use strata_test_utils::ArbitraryGenerator;

use crate::handlers::checkpoint::constants::{BRIDGE_GATEWAY_ACCT_SERIAL, MOCK_PREDICATE_KEY};

/// Builds mock signed checkpoint payloads for testing.
pub(crate) struct MockCheckpointBuilder {
    sequencer_predicate: SigningKey,
    checkpoint_predicate: SigningKey,
}

impl MockCheckpointBuilder {
    pub(crate) fn new() -> Self {
        // For testing we use ASM on `AlwaysAccept` predicate which accepts any valid schnorr
        // signature
        let sk = SigningKey::from_bytes(&MOCK_PREDICATE_KEY).expect("invalid mock predicate key");

        Self {
            sequencer_predicate: sk.clone(),
            checkpoint_predicate: sk,
        }
    }

    /// Generates a new checkpoint tip and the previous tip from the given parameters.
    pub(crate) fn gen_tips(
        &self,
        epoch: u32,
        genesis_l1_height: u32,
        ol_start_slot: u64,
        ol_end_slot: u64,
    ) -> (CheckpointTip, CheckpointTip) {
        let mut arb = ArbitraryGenerator::new();

        let start_blkid: OLBlockId = if ol_start_slot == 0 {
            OLBlockId::from(Buf32::zero())
        } else {
            arb.generate()
        };
        let prev_tip = CheckpointTip::new(
            epoch.saturating_sub(1),
            genesis_l1_height,
            OLBlockCommitment::new(ol_start_slot, start_blkid),
        );

        let end_blkid: OLBlockId = arb.generate();
        let new_tip = CheckpointTip::new(
            epoch,
            genesis_l1_height,
            OLBlockCommitment::new(ol_end_slot, end_blkid),
        );

        (prev_tip, new_tip)
    }

    /// Generates a mock checkpoint payload signed by the checkpoint predicate.
    pub(crate) fn build_payload(
        &self,
        prev_tip: &CheckpointTip,
        new_tip: &CheckpointTip,
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

        let l2_range = L2BlockRange::new(prev_tip.l2_commitment, new_tip.l2_commitment);
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

        CheckpointPayload::new(*new_tip, sidecar, proof).unwrap()
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
