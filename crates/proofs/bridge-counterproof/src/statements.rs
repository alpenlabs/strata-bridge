//! Bridge counterproof statements.

use zkaleido::{ZkVmEnv, ZkVmEnvSsz};

use crate::{
    genesis::{BridgeCounterproofGenesis, load_genesis},
    types::{CounterproofInput, CounterproofOutput},
};

/// Native entry point: loads genesis and runs the counterproof.
#[cfg(not(target_os = "zkvm"))]
pub fn process_counterproof(zkvm: &impl ZkVmEnv) {
    let genesis = load_genesis();
    process_counterproof_inner(zkvm, &genesis);
}

/// zkVM entry point: runs the counterproof.
#[cfg(target_os = "zkvm")]
pub fn process_counterproof(zkvm: &impl ZkVmEnv, genesis: BridgeCounterproofGenesis) {
    process_counterproof_inner(zkvm, &genesis);
}

/// Reads the SSZ input and commits the expected public values.
fn process_counterproof_inner(zkvm: &impl ZkVmEnv, _genesis: &BridgeCounterproofGenesis) {
    let CounterproofInput {
        game_idx,
        operator_pubkey,
        ..
    } = zkvm.read_ssz();

    zkvm.commit_ssz(&CounterproofOutput {
        game_idx,
        operator_pubkey,
    });
}
