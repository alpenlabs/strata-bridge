use strata_bridge_proof_protocol::{process_bridge_proof, BridgeProofInput, StrataBridgeState};
use strata_primitives::params::RollupParams;

fn main() {
    let bridge_proof_input: BridgeProofInput = sp1_zkvm::io::read();
    let rollup_params: RollupParams = sp1_zkvm::io::read();

    let strata_bridge_state = sp1_zkvm::io::read_vec();
    let strata_bridge_state: StrataBridgeState = borsh::from_slice(&strata_bridge_state).unwrap();

    let public_params =
        process_bridge_proof(bridge_proof_input, strata_bridge_state, rollup_params).unwrap();
    sp1_zkvm::io::commit(&public_params);
}
