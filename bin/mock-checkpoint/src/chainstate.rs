use arbitrary::{Arbitrary, Unstructured};
use strata_state::{chain_state::Chainstate, state_op::StateCache};

use crate::Args;

pub(crate) fn update_chainstate(chainstate: Chainstate, _args: &Args) -> Chainstate {
    let ccache = StateCache::new(chainstate);
    // TODO: make bridge modifications
    let wb = ccache.finalize();
    wb.into_toplevel()
}

/// Creates raw arbitrary chainstat
// TODO: maybe read from a file
pub(crate) fn create_chainstate() -> Chainstate {
    let mut raw = Unstructured::new(&[1, 2, 3, 4, 5, 6]);
    Arbitrary::arbitrary(&mut raw).unwrap()
}
