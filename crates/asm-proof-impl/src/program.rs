//! ASM STF [`ZkVmProgram`] definition.

use moho_runtime_impl::RuntimeInput;
use moho_types::MohoAttestation;
use ssz::{decode::Decode, encode::Encode};
use zkaleido::{
    DataFormatError, ProofType, PublicValues, ZkVmError, ZkVmHost, ZkVmInputBuilder,
    ZkVmInputResult, ZkVmProgram,
};

/// The ASM STF program for ZKVM proof generation and verification.
///
/// This implements [`ZkVmProgram`] to define how the ASM STF runtime input is serialized
/// into the ZKVM guest and how the resulting [`MohoAttestation`] is extracted from the
/// proof's public values.
#[derive(Debug)]
pub struct AsmStfProgram;

impl ZkVmProgram for AsmStfProgram {
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
