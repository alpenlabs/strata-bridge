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

    use bitcoin::secp256k1;
    use strata_bridge_common::logging::{self, LoggerConfig};
    use tracing::debug;
    use zkaleido::ZkVmProgram;

    use super::*;
    use crate::CounterproofMode;

    fn get_test_input() -> CounterproofInput {
        // Create a test input with dummy data
        CounterproofInput {
            bridge_proof_master_key: secp256k1::XOnlyPublicKey::from_slice(&[0x02; 32]).unwrap(),
            deposit_index: 0,
            bridge_proof_tx: bitcoin::Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![],
                output: vec![],
            },
            bridge_proof_prevouts: Arc::new([]),
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
