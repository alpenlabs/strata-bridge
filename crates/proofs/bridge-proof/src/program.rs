//! [`ZkVmProgram`] implementation for the bridge proof.

use ssz::{Decode, Encode};
use zkaleido::{
    DataFormatError, ProofType, PublicValues, ZkVmError, ZkVmHost, ZkVmInputBuilder,
    ZkVmInputResult, ZkVmProgram, ZkVmResult,
};

use crate::types::{BridgeProofInput, BridgeProofOutput};

/// Proves that an operator's [`OperatorClaimUnlock`](crate::OperatorClaimUnlock)
/// is recorded in the ASM bridge-v1 export-entries MMR at a given Moho state
#[derive(Debug)]
pub struct BridgeProofProgram;

impl ZkVmProgram for BridgeProofProgram {
    type Input = BridgeProofInput;
    type Output = BridgeProofOutput;

    fn name() -> String {
        "Bridge Proof".to_string()
    }

    fn proof_type() -> ProofType {
        ProofType::Groth16
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: ZkVmInputBuilder<'a>,
    {
        let mut builder = B::new();
        builder.write_buf(&input.as_ssz_bytes())?;
        builder.build()
    }

    fn process_output<H>(public_values: &PublicValues) -> ZkVmResult<Self::Output>
    where
        H: ZkVmHost,
    {
        BridgeProofOutput::from_ssz_bytes(public_values.as_bytes()).map_err(|e| {
            ZkVmError::OutputExtractionError {
                source: DataFormatError::Other(e.to_string()),
            }
        })
    }
}
