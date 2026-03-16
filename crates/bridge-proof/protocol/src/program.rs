use bitcoin::consensus::serialize;
use zkaleido::{ProofType, PublicValues, ZkVmInputResult, ZkVmProgram, ZkVmResult};
use zkaleido_native_adapter::NativeHost;

use crate::{
    process_bridge_proof_outer, BridgeProofInput, BridgeProofInputBorsh, BridgeProofPublicOutput,
};

/// The bridge proof program for ZKVM proof generation and verification.
///
/// This implements [`ZkVmProgram`] to define how the bridge proof input is serialized
/// into the ZKVM guest and how the resulting [`BridgeProofPublicOutput`] is extracted from the
/// proof's public values.
#[derive(Debug)]
pub struct BridgeProgram;

impl ZkVmProgram for BridgeProgram {
    type Input = BridgeProofInput;

    type Output = BridgeProofPublicOutput;

    fn name() -> String {
        "Bridge Proof".to_string()
    }

    fn proof_type() -> ProofType {
        zkaleido::ProofType::Groth16
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: zkaleido::ZkVmInputBuilder<'a>,
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
            .write_serde(&input.rollup_params)?
            .write_buf(&headers_buf)?
            .write_borsh(&borsh_input)?
            .build()
    }

    fn process_output<H>(public_values: &PublicValues) -> ZkVmResult<Self::Output>
    where
        H: zkaleido::ZkVmHost,
    {
        H::extract_borsh_public_output(public_values)
    }
}

impl BridgeProgram {
    /// get native host. This can be used for testing
    pub fn native_host() -> NativeHost {
        NativeHost::new(process_bridge_proof_outer)
    }

    /// Add this new convenience method
    pub fn execute(
        input: &<Self as ZkVmProgram>::Input,
    ) -> ZkVmResult<<Self as ZkVmProgram>::Output> {
        // Get the native host and delegate to the trait's execute method
        let host = Self::native_host();
        <Self as ZkVmProgram>::execute(input, &host)
    }
}
#[cfg(test)]
mod tests {
    use prover_test_utils::{
        extract_test_headers, get_strata_checkpoint_tx, get_withdrawal_fulfillment_tx,
        load_op_signature, load_test_rollup_params,
    };
    use strata_bridge_common::logging::{self, LoggerConfig};

    use super::*;

    fn get_input() -> BridgeProofInput {
        BridgeProofInput {
            rollup_params: load_test_rollup_params(),
            headers: extract_test_headers(),
            deposit_idx: 0,
            strata_checkpoint_tx: get_strata_checkpoint_tx(),
            withdrawal_fulfillment_tx: get_withdrawal_fulfillment_tx(),
            op_signature: load_op_signature(),
        }
    }

    #[test]
    fn test_native() {
        logging::init(LoggerConfig::new("test-native".to_string()));
        let input = get_input();
        let res = BridgeProgram::execute(&input);
        assert!(res.is_ok());
    }
}
