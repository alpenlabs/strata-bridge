use arbitrary::{Arbitrary, Unstructured};
use bitcoin::OutPoint;
use strata_bridge_common::tracing::info;
use strata_primitives::l1::{BitcoinAmount, OutputRef};
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

    info!("updating deposit entries in chainstate");
    // It is important to have deposit entry of idx n to be at the nth index because the only way
    // deposit table can be populated is by using `create_next_deposit` as done below.
    // For this we put dummy deposit entries at other places and put corresponding deposit entries
    // at the required index.
    let maxidx = dep_entries
        .iter()
        .map(|e| e.idx())
        .max()
        .unwrap_or_default() as usize;
    let mut new_entries = vec![dummy_entry(); maxidx + 1];

    for entry in dep_entries {
        new_entries[entry.idx() as usize] = entry.clone();
    }

    for entry in new_entries {
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

fn dummy_entry() -> DepositEntry {
    let txref = OutputRef(OutPoint::null());
    let operators = vec![0, 1, 2];
    let amt = BitcoinAmount::from_int_btc(10);
    DepositEntry::new(0, txref, operators, amt, None)
}
