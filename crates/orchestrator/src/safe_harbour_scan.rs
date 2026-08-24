//! Per-block scan that drives deposit sweeps and aborts while the safe harbour is active.

use strata_bridge_sm::deposit::{
    events::{DepositEvent, SafeHarbourAbortEvent, SweepRequestedEvent},
    state::DepositState,
};

use crate::{
    sm_registry::SMRegistry,
    sm_types::{SMEvent, SMId},
};

/// Enumerates the registry's deposits and seeds sweep and abort events while the safe harbour
/// is active. Returns nothing when the latch is not set.
///
/// Every state holding a live deposit UTXO — `Deposited` and the withdrawal states, whose
/// progress never touches the fixed N-of-N outpoint — gets [`DepositEvent::SweepRequested`]
/// carrying the frozen safe-harbour descriptor; safe-window deposits
/// (`Created`/`GraphGenerated`) get [`DepositEvent::SafeHarbourAbort`]. Runs once per buried
/// block, which is also the retry mechanism: the SM classifies replays as duplicates, so
/// re-emission is idempotent until each deposit leaves its scanned state.
pub fn safe_harbour_scan(registry: &SMRegistry) -> Vec<(SMId, SMEvent)> {
    let Some(address) = registry.safe_harbour_address() else {
        return Vec::new();
    };
    let safe_harbour_desc = address.as_descriptor();

    registry
        .deposits()
        .filter_map(|(&deposit_idx, sm)| {
            let event = match sm.state() {
                // Live deposit UTXO: sweep it, abandoning any withdrawal progress. A racing
                // payout is resolved on chain — whichever tx spends the outpoint first wins.
                DepositState::Deposited { .. }
                | DepositState::Assigned { .. }
                | DepositState::Fulfilled { .. }
                | DepositState::PayoutDescriptorReceived { .. }
                | DepositState::PayoutNoncesCollected { .. }
                | DepositState::CooperativePathFailed { .. } => {
                    DepositEvent::SweepRequested(SweepRequestedEvent {
                        safe_harbour_desc: safe_harbour_desc.clone(),
                    })
                }

                // Safe abort window: no partial signature gossiped yet.
                DepositState::Created { .. } | DepositState::GraphGenerated { .. } => {
                    DepositEvent::SafeHarbourAbort(SafeHarbourAbortEvent)
                }

                // A partial is gossiped from DepositNoncesCollected onward: these deposits
                // finish and become sweepable on reaching Deposited.
                DepositState::DepositNoncesCollected { .. }
                | DepositState::DepositPartialsCollected { .. } => return None,

                // Already in the sweep flow or terminal.
                DepositState::SweepNoncesPending { .. }
                | DepositState::SweepNoncesCollected { .. }
                | DepositState::Spent { .. }
                | DepositState::Aborted => return None,
            };

            Some((SMId::Deposit(deposit_idx), event.into()))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::OutPoint;
    use strata_bridge_primitives::types::DepositIdx;
    use strata_bridge_sm::deposit::{context::DepositSMCtx, machine::DepositSM};
    use strata_bridge_test_utils::{
        bridge_fixtures::random_p2tr_desc, musig2::generate_agg_nonce, prelude::generate_txid,
    };
    use strata_bridge_tx_graph::transactions::deposit::{
        DepositData, DepositTx, build_test_deposit_tx,
    };

    use super::*;
    use crate::testing::{
        INITIAL_BLOCK_HEIGHT, N_TEST_OPERATORS, TEST_DEPOSIT_AMOUNT, TEST_MAGIC_BYTES,
        TEST_POV_IDX, insert_deposit_with_graphs, test_empty_registry, test_operator_table,
        test_safe_harbour_address,
    };

    /// Inserts a deposit SM pinned to `state` (no graph SMs; the scan only reads deposits).
    fn insert_deposit_in_state(
        registry: &mut SMRegistry,
        deposit_idx: DepositIdx,
        state: DepositState,
    ) {
        let context = DepositSMCtx {
            deposit_idx,
            deposit_request_outpoint: OutPoint::default(),
            deposit_outpoint: OutPoint::default(),
            operator_table: test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX),
        };
        registry
            .insert_deposit(deposit_idx, DepositSM { context, state })
            .expect("test deposit indices must be unique");
    }

    /// Extracts the deposit-scoped event for `deposit_idx`, if any.
    fn scanned_event(events: &[(SMId, SMEvent)], deposit_idx: DepositIdx) -> Option<DepositEvent> {
        events.iter().find_map(|(id, event)| match (id, event) {
            (SMId::Deposit(idx), SMEvent::Deposit(boxed)) if *idx == deposit_idx => {
                Some(*boxed.clone())
            }
            _ => None,
        })
    }

    #[test]
    fn scan_is_empty_while_not_latched() {
        let mut registry = test_empty_registry();
        insert_deposit_in_state(
            &mut registry,
            0,
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
        );

        assert!(safe_harbour_scan(&registry).is_empty());
    }

    #[test]
    fn scan_sweeps_deposited_with_frozen_descriptor() {
        let mut registry = test_empty_registry();
        registry.activate_safe_harbour(test_safe_harbour_address());
        insert_deposit_in_state(
            &mut registry,
            0,
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
        );

        let events = safe_harbour_scan(&registry);
        assert_eq!(events.len(), 1);
        let Some(DepositEvent::SweepRequested(sweep)) = scanned_event(&events, 0) else {
            panic!("Deposited must be scanned into SweepRequested");
        };
        assert_eq!(
            &sweep.safe_harbour_desc,
            test_safe_harbour_address().as_descriptor(),
            "sweep must pay the frozen safe-harbour descriptor",
        );
    }

    #[test]
    fn scan_aborts_safe_window_deposits() {
        let mut registry = test_empty_registry();
        registry.activate_safe_harbour(test_safe_harbour_address());

        // A freshly registered deposit sits in Created.
        insert_deposit_with_graphs(&mut registry, 0);

        let events = safe_harbour_scan(&registry);
        assert!(
            matches!(
                scanned_event(&events, 0),
                Some(DepositEvent::SafeHarbourAbort(_))
            ),
            "Created must be scanned into SafeHarbourAbort",
        );
    }

    #[test]
    fn scan_sweeps_withdrawal_states() {
        let mut registry = test_empty_registry();
        registry.activate_safe_harbour(test_safe_harbour_address());

        insert_deposit_in_state(
            &mut registry,
            0,
            DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: 0,
                deadline: INITIAL_BLOCK_HEIGHT + 100,
                recipient_desc: random_p2tr_desc(),
            },
        );
        insert_deposit_in_state(
            &mut registry,
            1,
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: 0,
                fulfillment_txid: generate_txid(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: INITIAL_BLOCK_HEIGHT + 100,
            },
        );
        insert_deposit_in_state(
            &mut registry,
            2,
            DepositState::CooperativePathFailed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: 0,
                fulfillment_txid: generate_txid(),
            },
        );

        let events = safe_harbour_scan(&registry);
        assert_eq!(events.len(), 3);
        for deposit_idx in 0..3 {
            assert!(
                matches!(
                    scanned_event(&events, deposit_idx),
                    Some(DepositEvent::SweepRequested(_))
                ),
                "deposit {deposit_idx}: every live-UTXO withdrawal state must be swept",
            );
        }
    }

    #[test]
    fn scan_skips_states_that_finish_or_are_settled() {
        let mut registry = test_empty_registry();
        registry.activate_safe_harbour(test_safe_harbour_address());

        // Mid-signing: a partial signature is already gossiped, so the deposit must finish.
        insert_deposit_in_state(
            &mut registry,
            0,
            DepositState::DepositNoncesCollected {
                deposit_transaction: test_deposit_tx(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
                agg_nonce: generate_agg_nonce(),
                pubnonces: BTreeMap::new(),
                partial_signatures: BTreeMap::new(),
            },
        );
        // Terminal.
        insert_deposit_in_state(
            &mut registry,
            1,
            DepositState::Spent {
                fulfillment_txid: None,
                assignee: None,
            },
        );
        insert_deposit_in_state(&mut registry, 2, DepositState::Aborted);

        assert!(safe_harbour_scan(&registry).is_empty());
    }

    /// Fills the states that carry a deposit transaction; the scan never inspects it.
    fn test_deposit_tx() -> DepositTx {
        build_test_deposit_tx(
            &test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX),
            DepositData {
                deposit_idx: 99,
                deposit_request_outpoint: OutPoint::default(),
                magic_bytes: TEST_MAGIC_BYTES.into(),
            },
            TEST_DEPOSIT_AMOUNT,
        )
    }
}
