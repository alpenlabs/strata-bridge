#![no_main]
zkaleido_sp1_guest_env::entrypoint!(main);

#[cfg(target_os = "zkvm")]
use ssz::Decode;
use strata_bridge_proof::statements::process_bridge_proof;
#[cfg(target_os = "zkvm")]
use strata_bridge_proof::BridgeProofGenesis;
use zkaleido_sp1_guest_env::Sp1ZkVmEnv;

#[cfg(target_os = "zkvm")]
const GENESIS_BYTES: &[u8] = include_bytes!("../build/genesis.bin");

fn main() {
    #[cfg(target_os = "zkvm")]
    {
        let genesis = BridgeProofGenesis::from_ssz_bytes(GENESIS_BYTES)
            .expect("genesis.bin must SSZ-decode into BridgeProofGenesis");
        process_bridge_proof(&Sp1ZkVmEnv, genesis)
    }

    #[cfg(not(target_os = "zkvm"))]
    process_bridge_proof(&Sp1ZkVmEnv)
}
