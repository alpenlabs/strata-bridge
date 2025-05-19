//! Contains logic to handle proof generation.

use std::sync::Arc;

use ark_bn254::{Bn254, Fr};
use ark_groth16::Proof;
use bitcoin::Txid;
use strata_bridge_primitives::types::BitcoinBlockHeight;
use strata_bridge_proof_protocol::{BridgeProofInput, BridgeProofPublicOutput};
use strata_bridge_proof_snark::prover;

use crate::{
    contract_manager::{ExecutionConfig, OutputHandles},
    contract_state_machine::TransitionErr,
    errors::ContractManagerErr,
};

/// Prepares the data required to generate the bridge proof.
pub(super) fn prepare_proof_input(
    _cfg: &ExecutionConfig,
    _output_handles: Arc<OutputHandles>,
    _withdrawal_fulfillment_txid: Txid,
    _start_height: BitcoinBlockHeight,
) -> Result<BridgeProofInput, ContractManagerErr> {
    todo!()
}

/// Generates the proof, the scalars and the public outputs for the given input.
pub(super) fn generate_proof(
    input: &BridgeProofInput,
) -> Result<(Proof<Bn254>, [Fr; 1], BridgeProofPublicOutput), ContractManagerErr> {
    prover::sp1_prove(input).map_err(|e| {
        ContractManagerErr::TransitionErr(TransitionErr(format!(
            "could not generate proof due to {e:?}"
        )))
    })
}
