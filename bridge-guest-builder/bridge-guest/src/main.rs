// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use strata_bridge_proof_protocol2::process_bridge_proof_outer;
use zkaleido_sp1_adapter::Sp1ZkVmEnv;

fn main() {
    process_bridge_proof_outer2(&Sp1ZkVmEnv);
}
