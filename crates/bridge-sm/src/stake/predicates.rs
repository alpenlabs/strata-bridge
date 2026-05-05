//! Pure predicates over stake-graph data used by the state machine.

use bitcoin::{OutPoint, Transaction};
use strata_bridge_tx_graph::{stake_graph::StakeGraphSummary, transactions::prelude::StakeTx};

/// Returns true if the transaction spends the stake output of the stake transaction
/// without being the legitimate unstaking transaction.
pub(crate) fn is_slash_tx(summary: &StakeGraphSummary, tx: &Transaction) -> bool {
    let stake_outpoint = OutPoint {
        txid: summary.stake,
        vout: StakeTx::STAKE_VOUT,
    };
    let spends_stake_output = tx
        .input
        .iter()
        .any(|txin| txin.previous_output == stake_outpoint);
    spends_stake_output && tx.compute_txid() != summary.unstaking
}
