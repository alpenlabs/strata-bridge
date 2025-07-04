use arbitrary::{Arbitrary, Unstructured};
use strata_state::{bridge_state::DepositEntry, chain_state::Chainstate};

/// Chainstate wrapper which ensures the chainstate always has empty deposit table.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ChainstateWithEmptyDeposits(Chainstate);

impl ChainstateWithEmptyDeposits {
    /// Creates raw arbitrary chainstate.
    pub(crate) fn new() -> Self {
        let mut raw = Unstructured::new(&[]);
        let chst: Chainstate = Arbitrary::arbitrary(&mut raw).unwrap();
        // Make sure deposits_table is empty
        assert!(
            chst.deposits_table().is_empty(),
            "Chainstate deposits table is not empty"
        );
        Self(chst)
    }

    pub(crate) fn into_inner(self) -> Chainstate {
        self.0
    }
}

/// Updates deposit entries of given chainstate that had empty deposits.
pub(crate) fn update_deposit_entries(
    chainstate: ChainstateWithEmptyDeposits,
    dep_entries: &[DepositEntry],
) -> Chainstate {
    let mut chs = chainstate.into_inner();
    let dep_table = chs.deposits_table_mut();

    for entry in dep_entries {
        // Can only create Accepted deposit entry.
        let idx = dep_table.create_next_deposit(
            *entry.output(),
            entry.notary_operators().to_vec(),
            entry.amt(),
        );
        // Now update the state and withdrawal txid
        let dep_entry = dep_table.get_deposit_mut(idx).unwrap();
        dep_entry.set_state(entry.deposit_state().clone());
        dep_entry.set_withdrawal_request_txid(entry.withdrawal_request_txid());
    }
    chs
}
