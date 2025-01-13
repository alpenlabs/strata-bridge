use bitcoin::consensus::serialize;
use strata_zkvm::{ProofType, PublicValues, ZkVmInputResult, ZkVmProver, ZkVmResult};

use crate::{BridgeProofInput, BridgeProofInputBorsh, BridgeProofOutput};

pub struct BridgeProver;

impl ZkVmProver for BridgeProver {
    type Input = BridgeProofInput;

    type Output = BridgeProofOutput;

    fn proof_type() -> ProofType {
        strata_zkvm::ProofType::Groth16
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: strata_zkvm::ZkVmInputBuilder<'a>,
    {
        let mut input_builder = B::new();

        let headers_buf = input.headers.iter().fold(
            Vec::with_capacity(input.headers.len() * 80),
            |mut acc, header| {
                acc.extend_from_slice(&serialize(header));
                acc
            },
        );
        let borsh_input: BridgeProofInputBorsh = input.clone().into();

        input_builder
            .write_buf(&headers_buf)?
            .write_serde(&input.rollup_params)?
            .write_borsh(&borsh_input)?
            .build()
    }

    fn process_output<H>(public_values: &PublicValues) -> ZkVmResult<Self::Output>
    where
        H: strata_zkvm::ZkVmHost,
    {
        H::extract_borsh_public_output(public_values)
    }
}
