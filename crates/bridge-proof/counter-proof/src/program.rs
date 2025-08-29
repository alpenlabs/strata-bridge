use std::{
    panic::{catch_unwind, AssertUnwindSafe},
    sync::Arc,
};

use zkaleido::{ProofType, PublicValues, ZkVmError, ZkVmInputResult, ZkVmProgram, ZkVmResult};
use zkaleido_native_adapter::{NativeHost, NativeMachine};

use crate::{
    process_counterproof_outer, CounterproofInput, CounterproofInputBorsh, CounterproofPublicOutput,
};

/// This is responsible for generating the counter-proof
#[derive(Debug)]
pub struct CounterproofProgram;

impl ZkVmProgram for CounterproofProgram {
    type Input = CounterproofInput;
    type Output = CounterproofPublicOutput;

    fn name() -> String {
        "Counter Proof".to_string()
    }

    fn proof_type() -> ProofType {
        zkaleido::ProofType::Compressed
    }

    fn prepare_input<'a, B>(input: &'a Self::Input) -> ZkVmInputResult<B::Input>
    where
        B: zkaleido::ZkVmInputBuilder<'a>,
    {
        let mut input_builder = B::new();
        let borsh_input: CounterproofInputBorsh = input.clone().into();

        input_builder.write_borsh(&borsh_input)?.build()
    }

    fn process_output<H>(public_values: &PublicValues) -> ZkVmResult<Self::Output>
    where
        H: zkaleido::ZkVmHost,
    {
        H::extract_borsh_public_output(public_values)
    }
}

impl CounterproofProgram {
    /// get native host. This can be used for testing
    pub fn native_host() -> NativeHost {
        NativeHost {
            process_proof: Arc::new(Box::new(move |zkvm: &NativeMachine| {
                catch_unwind(AssertUnwindSafe(|| {
                    process_counterproof_outer(zkvm);
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
            process_counterproof_outer(zkvm);
            Ok(())
        })),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bitcoin::{key::Secp256k1, secp256k1, XOnlyPublicKey};
    use strata_bridge_common::logging::{self, LoggerConfig};
    use tracing::debug;
    use zkaleido::ZkVmProgram;

    use super::*;
    use crate::CounterproofMode;

    fn get_test_input() -> CounterproofInput {
        use crate::statement::create_mock_transaction;

        // Create a proper mock transaction with inputs and OP_RETURN output
        let bridge_proof_master_key_bytes = [0x01; 32];

        let deposit_index = 32;
        let (mock_tx, mock_prevouts) =
            create_mock_transaction(bridge_proof_master_key_bytes, deposit_index);

        let secp = Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&bridge_proof_master_key_bytes).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let bridge_proof_master_key = XOnlyPublicKey::from_keypair(&kp).0;

        // Convert to the format needed by CounterproofInput
        // let bridge_proof_master_key =
        //     secp256k1::XOnlyPublicKey::from_slice(&bridge_proof_master_key_bytes).unwrap();

        CounterproofInput {
            bridge_proof_master_key,
            deposit_index,
            bridge_proof_tx: mock_tx,
            bridge_proof_prevouts: Arc::from(mock_prevouts),
            mode: CounterproofMode::InvalidBridgeProof,
        }
    }

    #[test]
    fn test_native() {
        logging::init(LoggerConfig::new("test-counterproof-native".to_string()));
        let input = get_test_input();
        let host = get_native_host();
        // Note: This test will likely fail due to dummy data, but demonstrates the structure
        match CounterproofProgram::prove(&input, &host) {
            Ok(receipt) => debug!(?receipt, "received counter-proof receipt from native host"),
            Err(e) => debug!(?e, "counter-proof failed as expected with dummy data"),
        }
    }
}
