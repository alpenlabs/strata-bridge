#![no_main]
zkaleido_sp1_guest_env::entrypoint!(main);

#[cfg(target_os = "zkvm")]
use ssz::Decode;
use strata_bridge_counterproof::statements::process_counterproof;
#[cfg(target_os = "zkvm")]
use strata_bridge_counterproof::BridgeCounterproofGenesis;
use zkaleido_sp1_guest_env::Sp1ZkVmEnv;

#[cfg(target_os = "zkvm")]
const GENESIS_BYTES: &[u8] = include_bytes!("../build/genesis.bin");

fn main() {
    #[cfg(target_os = "zkvm")]
    {
        let genesis = BridgeCounterproofGenesis::from_ssz_bytes(GENESIS_BYTES)
            .expect("genesis.bin must SSZ-decode into BridgeCounterproofGenesis");
        process_counterproof(&Sp1ZkVmEnv, genesis)
    }

    #[cfg(not(target_os = "zkvm"))]
    process_counterproof(&Sp1ZkVmEnv)
}
