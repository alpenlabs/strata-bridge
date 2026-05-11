//! [`ZkVmProgram`] implementation for the bridge counterproof.

use ssz::{Decode, Encode};
use zkaleido::{
    DataFormatError, ProofType, PublicValues, ZkVmError, ZkVmHost, ZkVmInputBuilder,
    ZkVmInputResult, ZkVmProgram, ZkVmResult,
};

use crate::types::{CounterproofInput, CounterproofOutput};

/// Proves that an operator's published bridge proof is invalid.
#[derive(Debug)]
pub struct CounterproofProgram;

impl ZkVmProgram for CounterproofProgram {
    type Input = CounterproofInput;
    type Output = CounterproofOutput;

    fn name() -> String {
        "bridge_counterproof".to_string()
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
        CounterproofOutput::from_ssz_bytes(public_values.as_bytes()).map_err(|e| {
            ZkVmError::OutputExtractionError {
                source: DataFormatError::Other(e.to_string()),
            }
        })
    }
}
