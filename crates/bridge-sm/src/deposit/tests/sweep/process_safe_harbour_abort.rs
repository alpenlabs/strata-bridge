//! Unit Tests for process_safe_harbour_abort
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::OutPoint;

    use crate::{
        deposit::{
            errors::DSMError,
            events::{DepositEvent, SafeHarbourAbortEvent},
            state::DepositState,
            tests::*,
        },
        signals::{DepositSignal, DepositToGraph},
    };

    /// The graph-teardown signal carries the deposit-request txid, since no on-chain takeback
    /// exists for a safe-harbour abort. The test context uses `OutPoint::default()` as the DRT
    /// outpoint.
    fn abort_signal() -> DepositSignal {
        DepositSignal::ToGraph(DepositToGraph::DepositRequestTakenBack {
            deposit_idx: TEST_DEPOSIT_IDX,
            takeback_txid: OutPoint::default().txid,
        })
    }

    /// Tests that the abort from `Created` reaches `Aborted` and tears down the graphs.
    #[test]
    fn test_safe_harbour_abort_from_created() {
        test_deposit_transition(DepositTransition {
            from_state: DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
            },
            event: DepositEvent::SafeHarbourAbort(SafeHarbourAbortEvent),
            expected_state: DepositState::Aborted,
            expected_duties: vec![],
            expected_signals: vec![abort_signal()],
        });
    }

    /// Tests that the abort from `GraphGenerated` reaches `Aborted` and tears down the graphs.
    #[test]
    fn test_safe_harbour_abort_from_graph_generated() {
        test_deposit_transition(DepositTransition {
            from_state: DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
                pubnonces: BTreeMap::new(),
            },
            event: DepositEvent::SafeHarbourAbort(SafeHarbourAbortEvent),
            expected_state: DepositState::Aborted,
            expected_duties: vec![],
            expected_signals: vec![abort_signal()],
        });
    }

    /// Tests that the abort replayed by the per-block scan against an already-aborted deposit is
    /// a non-fatal duplicate.
    #[test]
    fn test_safe_harbour_abort_in_aborted_is_duplicate() {
        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: DepositState::Aborted,
            event: DepositEvent::SafeHarbourAbort(SafeHarbourAbortEvent),
            expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
        });
    }

    /// Tests that the abort is invalid outside the safe window: a partial signature is gossiped
    /// from DepositNoncesCollected onward, and live-UTXO deposits are swept instead of aborted.
    #[test]
    fn test_safe_harbour_abort_outside_safe_window_is_invalid() {
        let states = vec![
            DepositState::DepositNoncesCollected {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                pubnonces: BTreeMap::new(),
                partial_signatures: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                deposit_transaction: test_deposit_txn().as_ref().clone(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::SweepNoncesPending {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                sweep_tx: test_sweep_txn(random_p2tr_desc()),
                sweep_nonces: BTreeMap::new(),
            },
            DepositState::Spent {
                fulfillment_txid: None,
                assignee: None,
            },
        ];

        for state in states {
            test_deposit_invalid_transition(DepositInvalidTransition {
                from_state: state,
                event: DepositEvent::SafeHarbourAbort(SafeHarbourAbortEvent),
                expected_error: |e| matches!(e, DSMError::InvalidEvent { .. }),
            });
        }
    }
}
