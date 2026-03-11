//! ASM STF [`ZkVmProgram`] definition.

use moho_runtime_impl::RuntimeInput;
use moho_types::MohoAttestation;
use ssz::{decode::Decode, encode::Encode};
use strata_asm_spec::StrataAsmSpec;
use zkaleido::{
    DataFormatError, ProofType, PublicValues, ZkVmError, ZkVmHost, ZkVmInputBuilder,
    ZkVmInputResult, ZkVmProgram, ZkVmResult,
};
use zkaleido_native_adapter::NativeHost;

use crate::statements::process_asm_stf;

/// The ASM STF program for ZKVM proof generation and verification.
///
/// This implements [`ZkVmProgram`] to define how the ASM STF runtime input is serialized
/// into the ZKVM guest and how the resulting [`MohoAttestation`] is extracted from the
/// proof's public values.
#[derive(Debug)]
pub struct AsmStfProofProgram;

impl ZkVmProgram for AsmStfProofProgram {
    type Input = RuntimeInput;
    type Output = MohoAttestation;

    fn name() -> String {
        "ASM STF".to_string()
    }

    fn proof_type() -> ProofType {
        ProofType::Groth16
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: ZkVmInputBuilder<'a>,
    {
        let mut input_builder = B::new();
        input_builder.write_buf(&input.as_ssz_bytes())?;
        input_builder.build()
    }

    fn process_output<H>(public_values: &PublicValues) -> zkaleido::ZkVmResult<Self::Output>
    where
        H: ZkVmHost,
    {
        MohoAttestation::from_ssz_bytes(public_values.as_bytes()).map_err(|e| {
            ZkVmError::OutputExtractionError {
                source: DataFormatError::Other(e.to_string()),
            }
        })
    }
}

impl AsmStfProofProgram {
    /// get native host. This can be used for testing
    pub fn native_host(spec: StrataAsmSpec) -> NativeHost {
        NativeHost::new(move |zkvm| {
            process_asm_stf(zkvm, &spec);
        })
    }

    /// Executes the checkpoint program using the native host for testing.
    pub fn execute(
        input: &<Self as ZkVmProgram>::Input,
        spec: StrataAsmSpec,
    ) -> ZkVmResult<<Self as ZkVmProgram>::Output> {
        // Get the native host and delegate to the trait's execute method
        let host = Self::native_host(spec);
        <Self as ZkVmProgram>::execute(input, &host)
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::Block;
    use moho_runtime_impl::RuntimeInput;
    use moho_runtime_interface::MohoProgram;
    use moho_types::{ExportState, MohoState};
    use strata_asm_common::{AnchorState, AsmHistoryAccumulatorState, AuxData, ChainViewState};
    use strata_asm_params::{AsmParams, SubprotocolInstance};
    use strata_asm_spec::StrataAsmSpec;
    use strata_btc_types::{BlockHashExt, GenesisL1View};
    use strata_btc_verification::HeaderVerificationState;
    use strata_identifiers::L1BlockCommitment;
    use strata_l1_txfmt::MagicBytes;
    use strata_predicate::PredicateKey;

    use crate::{
        moho_program::{
            input::{AsmStepInput, L1Block},
            program::AsmStfProgram,
        },
        program::AsmStfProofProgram,
    };

    fn load_test_blocks() -> Vec<Block> {
        let bytes = std::fs::read("../../test-data/blocks.bin").expect("Failed to read blocks.bin");
        bincode::deserialize(&bytes).expect("Failed to deserialize blocks")
    }

    fn create_asm_step_input() -> AsmStepInput {
        let blocks = load_test_blocks();
        let block = blocks
            .into_iter()
            .next()
            .expect("expected at least one block");
        AsmStepInput {
            block: L1Block(block),
            aux_data: AuxData::default(),
        }
    }

    fn create_genesis_l1_view_to_process_block(block: &Block) -> GenesisL1View {
        let genesis_block_hash = block.header.prev_blockhash;
        let genesis_block_height = block.bip34_block_height().unwrap() - 1;
        let genesis_block = L1BlockCommitment::new(
            genesis_block_height as u32,
            genesis_block_hash.to_l1_block_id(),
        );

        GenesisL1View {
            blk: genesis_block,
            next_target: block.header.bits.to_consensus(),
            epoch_start_timestamp: 0,
            last_11_timestamps: [0u32; 11],
        }
    }

    fn create_genesis_anchor_state(block: &Block) -> AnchorState {
        let genesis_view = create_genesis_l1_view_to_process_block(block);
        let pow_state = HeaderVerificationState::new(bitcoin::Network::Signet, &genesis_view);
        let chain_view = ChainViewState {
            pow_state,
            history_accumulator: AsmHistoryAccumulatorState::new(genesis_view.blk.height() as u64),
        };

        AnchorState {
            chain_view,
            sections: Vec::new(),
        }
    }

    fn create_asm_spec(genesis_view: GenesisL1View) -> StrataAsmSpec {
        let subprotocols: Vec<SubprotocolInstance> = serde_json::from_str(
            r#"[
                {"Admin":{"strata_administrator":{"keys":["02bedfa2fa42d906565519bee43875608a09e06640203a6c7a43569150c7cbe7c5"],"threshold":1},"strata_sequencer_manager":{"keys":["03cf59a1a5ef092ced386f2651b610d3dd2cc6806bb74a8eab95c1f3b2f3d81772","02343edde4a056e00af99aa49de60df03859d1b79ebbc4f3f6da8fbd0053565de3"],"threshold":1},"confirmation_depth":144,"max_seqno_gap":10}},
                {"Checkpoint":{"sequencer_predicate":"Sp1Groth16","checkpoint_predicate":"AlwaysAccept","genesis_l1_height":3334849731,"genesis_ol_blkid":"c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6"}},
                {"Bridge":{"operators":["02becdf7aab195ab0a42ba2f2eca5b7fa5a246267d802c627010e1672f08657f70"],"denomination":0,"assignment_duration":0,"operator_fee":0,"recovery_delay":0}}
              ]"#,
        )
        .expect("failed to deserialize AsmParams");
        let params = AsmParams {
            magic: MagicBytes::new(*b"ALPN"),
            l1_view: genesis_view,
            subprotocols,
        };
        StrataAsmSpec::from_asm_params(&params)
    }

    fn create_moho_prestate(block: &Block) -> MohoState {
        let anchor_state = create_genesis_anchor_state(block);
        let inner_state = AsmStfProgram::compute_state_commitment(&anchor_state)
            .into_inner()
            .into();

        MohoState {
            inner_state,
            next_predicate: PredicateKey::always_accept(),
            export_state: ExportState::new(vec![]),
        }
    }

    fn create_runtime_input(step_input: &AsmStepInput) -> RuntimeInput {
        let inner_pre_state = create_genesis_anchor_state(&step_input.block.0);
        let moho_pre_state = create_moho_prestate(&step_input.block.0);
        RuntimeInput::new(
            moho_pre_state,
            borsh::to_vec(&inner_pre_state).unwrap(),
            borsh::to_vec(step_input).unwrap(),
        )
    }

    #[test]
    fn test_stf() {
        let step_input = create_asm_step_input();
        let l1view = create_genesis_l1_view_to_process_block(&step_input.block.0);
        let spec = create_asm_spec(l1view);

        let runtime_input = create_runtime_input(&step_input);

        let output = AsmStfProofProgram::execute(&runtime_input, spec).unwrap();
        dbg!(output);
    }
}
