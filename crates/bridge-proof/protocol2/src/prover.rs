use bitcoin::consensus::serialize;
use zkaleido::{ProofType, PublicValues, ZkVmInputResult, ZkVmProver, ZkVmResult};

use crate::{BridgeProofInput, BridgeProofInputBorsh, BridgeProofOutput};

pub(crate) struct BridgeProver;

impl ZkVmProver for BridgeProver {
    type Input = BridgeProofInput;

    type Output = BridgeProofOutput;

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
            .write_buf(&headers_buf)?
            .write_serde(&input.rollup_params)?
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use zkaleido_native_adapter::{NativeHost, NativeMachine};

    use crate::{process_bridge_proof_outer, BridgeProofInput};

    pub fn get_native_host() -> NativeHost {
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                process_bridge_proof_outer(zkvm);
                Ok(())
            })),
        }
    }

    #[test]
    fn test_native() {}
}
