use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
};

use bitcoin::consensus::serialize;
use zkaleido::{ProofType, PublicValues, ZkVmError, ZkVmInputResult, ZkVmProgram, ZkVmResult};
use zkaleido_native_adapter::{NativeHost, NativeMachine};

use crate::{
    process_bridge_proof_outer, BridgeProofInput, BridgeProofInputBorsh, BridgeProofPublicOutput,
};

/// This is responsible for generating the proof
// TODO: zkaleido maybe add a display/debug trait to ZkVmProgram
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
            .write_serde(&input.pegout_graph_params)?
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
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                catch_unwind(AssertUnwindSafe(|| {
                    process_bridge_proof_outer(zkvm);
                }))
                .map_err(|_| ZkVmError::ExecutionError(Self::name()))?;
                Ok(())
            })),
        }
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
/// get native host. This can be used for testing
pub fn get_native_host() -> NativeHost {
    NativeHost {
        process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
            process_bridge_proof_outer(zkvm);
            Ok(())
        })),
    }
}

#[cfg(test)]
mod tests {
    use alpen_bridge_params::prelude::PegOutGraphParams;
    use bitcoin::hashes::serde::Serialize;
    use borsh::BorshSerialize;
    use prover_test_utils::{
        extract_test_headers, get_strata_checkpoint_tx, get_withdrawal_fulfillment_tx,
        load_op_signature, load_test_rollup_params,
    };
    use sp1_sdk::{SP1Proof, SP1Stdin, SP1VerifyingKey};
    use strata_bridge_common::logging::{self, LoggerConfig};
    use strata_primitives::bridge;
    use tracing::debug;
    use zkaleido::ZkVmProgram;

    use super::*;

    fn get_input() -> BridgeProofInput {
        let pegout_graph_params = PegOutGraphParams::default();

        BridgeProofInput {
            rollup_params: load_test_rollup_params(),
            pegout_graph_params,
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
        let host = get_native_host();
        let receipt = BridgeProgram::prove(&input, &host).unwrap();
        debug!(?receipt, "received proof receipt from native host");
    }

    fn write_serde<T: Serialize>(input: &mut SP1Stdin, item: &T) {
        input.write(item);
    }

    fn write_borsh<T: BorshSerialize>(input: &mut SP1Stdin, item: &T) {
        let slice = borsh::to_vec(item).unwrap();
        write_buf(input, &slice);
    }

    fn write_buf(input: &mut SP1Stdin, item: &[u8]) {
        input.write_slice(item);
    }

    #[test]
    fn test_another() {
        let mut input = SP1Stdin::new();
        let bridge_proof_input = get_input();

        let headers_buf = bridge_proof_input.headers.iter().fold(
            Vec::with_capacity(bridge_proof_input.headers.len() * 80),
            |mut acc, header| {
                acc.extend_from_slice(&serialize(header));
                acc
            },
        );

        write_serde(&mut input, &bridge_proof_input.rollup_params);
        write_serde(&mut input, &bridge_proof_input.pegout_graph_params);
        write_buf(&mut input, &headers_buf);
        write_borsh(&mut input, &bridge_proof_input.withdrawal_fulfillment_tx);

        use std::{
            fs::File,
            io::{Read, Write},
        };
        let mut file = File::create("test_input.bin").expect("Failed to create file");
        let encoded = bincode::serialize(&input).expect("Failed to serialize input with bincode");
        file.write_all(&encoded)
            .expect("Failed to write encoded input to file");
        file.flush().expect("Failed to flush file");

        let mut file = File::open("test_input.bin").expect("Failed to open file");
        let mut encoded = Vec::new();
        file.read_to_end(&mut encoded).expect("Failed to read file");

        let decoded: SP1Stdin =
            bincode::deserialize(&encoded).expect("Failed to deserialize input");
        println!("Absiehk decode {:?}", decoded);
    }
}

// input_builder
//             .write_serde(&input.rollup_params)?
//             .write_serde(&input.pegout_graph_params)?
//             .write_buf(&headers_buf)?
//             .write_borsh(&borsh_input)?
//             .build()
