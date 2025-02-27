#![expect(incomplete_features)] // the generic_const_exprs feature is incomplete
#![feature(generic_const_exprs)]
// but necessary for using const generic bounds in

// These two lines are necessary for the program to properly compile.
//
// Under the hood, we wrap your main function with some extra code so that it behaves properly
// inside the zkVM.
#![no_main]
sp1_zkvm::entrypoint!(main);

use strata_bridge_proof_protocol::process_bridge_proof_outer;
use zkaleido_sp1_adapter::Sp1ZkVmEnv;

fn main() {
    process_bridge_proof_outer(&Sp1ZkVmEnv);
}
