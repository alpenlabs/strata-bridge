#![no_main]
zkaleido_sp1_guest_env::entrypoint!(main);

use ssz::Decode;
use strata_bridge_counterproof::{BridgeCounterproofGenesis, statements::process_counterproof};
use zkaleido_sp1_guest_env::Sp1ZkVmEnv;

const GENESIS_BYTES: &[u8] = include_bytes!("../build/genesis.bin");

fn main() {
    let genesis = BridgeCounterproofGenesis::from_ssz_bytes(GENESIS_BYTES)
        .expect("genesis.bin must SSZ-decode into BridgeCounterproofGenesis");
    process_counterproof(&Sp1ZkVmEnv, genesis)
}
