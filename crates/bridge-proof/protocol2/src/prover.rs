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

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use strata_primitives::buf::Buf64;
    use zkaleido::ZkVmProver;
    use zkaleido_native_adapter::{NativeHost, NativeMachine};

    use super::BridgeProver;
    use crate::{
        process_bridge_proof_outer,
        test_data::test_data_loader::{
            extract_test_headers, get_strata_checkpoint_tx, get_withdrawal_fulfillment_tx,
            header_verification_state, load_test_chainstate, load_test_rollup_params,
        },
        BridgeProofInput,
    };

    fn get_native_host() -> NativeHost {
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                process_bridge_proof_outer(zkvm);
                Ok(())
            })),
        }
    }

    fn get_input() -> BridgeProofInput {
        BridgeProofInput {
            rollup_params: load_test_rollup_params(),
            headers: extract_test_headers(),
            chain_state: load_test_chainstate(),
            header_vs: header_verification_state(),
            deposit_idx: 0,
            strata_checkpoint_tx: get_strata_checkpoint_tx(),
            withdrawal_fulfillment_tx: get_withdrawal_fulfillment_tx(),
            op_signature: Buf64::zero(),
        }
    }

    #[test]
    fn test_native() {
        let input = get_input();
        let host = get_native_host();
        let receipt = BridgeProver::prove(&input, &host).unwrap();
        dbg!(receipt);
    }
}
