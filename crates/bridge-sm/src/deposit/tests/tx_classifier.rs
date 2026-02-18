//! Unit tests for the [`TxClassifier`] implementation on [`DepositSM`].
//!
//! These are exhaustive unit tests (not proptests) because classify_tx's
//! behavior depends on the state *variant*, not the field values within each
//! variant. Enumerating every variant gives guaranteed exhaustive coverage.

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::{
        deposit::tests::*,
        testing::fixtures::{test_payout_tx, test_takeback_tx},
        tx_classifier::TxClassifier,
    };

    // --- State constructors ---

    /// States that have a deposit request outpoint (pre-deposit).
    fn pre_deposit_states() -> Vec<DepositState> {
        vec![
            DepositState::Created {
                last_block_height: LATER_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                linked_graphs: Default::default(),
            },
            DepositState::GraphGenerated {
                last_block_height: LATER_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                pubnonces: Default::default(),
            },
            DepositState::DepositNoncesCollected {
                last_block_height: LATER_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: Default::default(),
                pubnonces: Default::default(),
            },
            DepositState::DepositPartialsCollected {
                last_block_height: LATER_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
            },
        ]
    }

    /// States that expect deposit confirmation (signing-complete subset of pre-deposit).
    fn deposit_confirmation_states() -> Vec<DepositState> {
        let h = LATER_BLOCK_HEIGHT;
        vec![
            DepositState::DepositNoncesCollected {
                last_block_height: h,
                deposit_transaction: test_deposit_txn(),
                agg_nonce: generate_agg_nonce(),
                partial_signatures: Default::default(),
                pubnonces: Default::default(),
            },
            DepositState::DepositPartialsCollected {
                last_block_height: h,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
            },
        ]
    }

    /// Early pre-deposit states that do NOT yet expect deposit confirmation.
    fn early_pre_deposit_states() -> Vec<DepositState> {
        let h = LATER_BLOCK_HEIGHT;
        vec![
            DepositState::Created {
                last_block_height: h,
                deposit_transaction: test_deposit_txn(),
                linked_graphs: Default::default(),
            },
            DepositState::GraphGenerated {
                last_block_height: h,
                deposit_transaction: test_deposit_txn(),
                pubnonces: Default::default(),
            },
        ]
    }

    fn assigned_state() -> DepositState {
        DepositState::Assigned {
            last_block_height: LATER_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            deadline: LATER_BLOCK_HEIGHT + 15,
            recipient_desc: random_p2tr_desc(),
        }
    }

    /// States that expect a payout (deposit spend).
    fn payout_pending_states() -> Vec<DepositState> {
        let h = LATER_BLOCK_HEIGHT;
        let num_operators = test_operator_table().cardinality() as u32;
        let nonces: BTreeMap<_, _> = (0..num_operators)
            .map(|idx| (idx, generate_pubnonce()))
            .collect();
        let agg_nonce = musig2::AggNonce::sum(nonces.values().cloned());

        vec![
            DepositState::PayoutNoncesCollected {
                last_block_height: h,
                assignee: TEST_ASSIGNEE,
                operator_desc: random_p2tr_desc(),
                cooperative_payment_deadline: h + 1008,
                payout_nonces: nonces,
                payout_aggregated_nonce: agg_nonce,
                payout_partial_signatures: BTreeMap::new(),
            },
            DepositState::CooperativePathFailed {
                last_block_height: h,
            },
        ]
    }

    /// One representative of every state variant.
    fn all_state_variants() -> Vec<DepositState> {
        let h = LATER_BLOCK_HEIGHT;
        let mut states = pre_deposit_states();
        states.push(DepositState::Deposited {
            last_block_height: h,
        });
        states.push(assigned_state());
        states.push(DepositState::Fulfilled {
            last_block_height: h,
            assignee: TEST_ASSIGNEE,
            fulfillment_txid: generate_txid(),
            fulfillment_height: h,
            cooperative_payout_deadline: h + 1008,
        });
        states.push(DepositState::PayoutDescriptorReceived {
            last_block_height: h,
            assignee: TEST_ASSIGNEE,
            cooperative_payment_deadline: h + 1008,
            operator_desc: random_p2tr_desc(),
            payout_nonces: BTreeMap::new(),
        });
        states.extend(payout_pending_states());
        states.push(DepositState::Spent);
        states.push(DepositState::Aborted);
        states
    }

    // --- Positive tests: classify_tx returns the correct event ---

    #[test]
    fn classify_tx_recognizes_takeback_in_all_pre_deposit_states() {
        let cfg = test_deposit_sm_cfg();
        for state in pre_deposit_states() {
            let sm = create_sm(state);
            let drt = sm
                .deposit_request_outpoint()
                .expect("pre-deposit states must have DRT outpoint");
            let result = sm.classify_tx(&cfg, &test_takeback_tx(drt), LATER_BLOCK_HEIGHT);
            assert!(
                matches!(result, Some(DepositEvent::UserTakeBack(_))),
                "expected Some(UserTakeBack) but got {result:?}"
            );
        }
    }

    #[test]
    fn classify_tx_recognizes_deposit_confirmation() {
        let cfg = test_deposit_sm_cfg();
        let deposit_tx = test_deposit_txn().as_ref().clone();
        for state in deposit_confirmation_states() {
            let sm = create_sm(state);
            let result = sm.classify_tx(&cfg, &deposit_tx, LATER_BLOCK_HEIGHT);
            assert!(
                matches!(result, Some(DepositEvent::DepositConfirmed(_))),
                "expected Some(DepositConfirmed) but got {result:?}"
            );
        }
    }

    #[test]
    fn classify_tx_recognizes_fulfillment() {
        let cfg = test_deposit_sm_cfg();
        let sm = create_sm(assigned_state());
        let result = sm.classify_tx(&cfg, &test_fulfillment_txn(), LATER_BLOCK_HEIGHT);
        assert!(
            matches!(result, Some(DepositEvent::FulfillmentConfirmed(_))),
            "expected Some(FulfillmentConfirmed) but got {result:?}"
        );
    }

    #[test]
    fn classify_tx_recognizes_payout_in_all_payout_pending_states() {
        let cfg = test_deposit_sm_cfg();
        for state in payout_pending_states() {
            let sm = create_sm(state);
            let payout_tx = test_payout_tx(sm.context().deposit_outpoint());
            let result = sm.classify_tx(&cfg, &payout_tx, LATER_BLOCK_HEIGHT);
            assert!(
                matches!(result, Some(DepositEvent::PayoutConfirmed(_))),
                "expected Some(PayoutConfirmed) but got {result:?}"
            );
        }
    }

    // --- Negative tests: classify_tx returns None ---

    #[test]
    fn classify_tx_ignores_irrelevant_tx_in_all_states() {
        let cfg = test_deposit_sm_cfg();
        let random_outpoint = OutPoint {
            txid: generate_txid(),
            vout: 99,
        };
        let irrelevant_tx = generate_spending_tx(random_outpoint, &[]);

        for state in all_state_variants() {
            let sm = create_sm(state);
            let result = sm.classify_tx(&cfg, &irrelevant_tx, LATER_BLOCK_HEIGHT);
            assert!(result.is_none(), "expected None but got {:?}", result);
        }
    }

    #[test]
    fn classify_tx_returns_none_in_terminal_states() {
        let cfg = test_deposit_sm_cfg();
        let terminal = [DepositState::Spent, DepositState::Aborted];
        let deposit_tx = test_deposit_txn().as_ref().clone();
        let fulfillment_tx = test_fulfillment_txn();

        for state in terminal {
            let sm = create_sm(state);
            let payout_tx = test_payout_tx(sm.context().deposit_outpoint());

            let result = sm.classify_tx(&cfg, &deposit_tx, LATER_BLOCK_HEIGHT);
            assert!(
                result.is_none(),
                "expected None for deposit tx but got {:?}",
                result
            );
            let result = sm.classify_tx(&cfg, &fulfillment_tx, LATER_BLOCK_HEIGHT);
            assert!(
                result.is_none(),
                "expected None for fulfillment tx but got {:?}",
                result
            );
            let result = sm.classify_tx(&cfg, &payout_tx, LATER_BLOCK_HEIGHT);
            assert!(
                result.is_none(),
                "expected None for payout tx but got {:?}",
                result
            );
        }
    }

    #[test]
    fn classify_tx_ignores_deposit_tx_in_early_states() {
        let cfg = test_deposit_sm_cfg();
        let deposit_tx = test_deposit_txn().as_ref().clone();

        for state in early_pre_deposit_states() {
            let sm = create_sm(state);
            let result = sm.classify_tx(&cfg, &deposit_tx, LATER_BLOCK_HEIGHT);
            assert!(result.is_none(), "expected None but got {:?}", result);
        }
    }

    #[test]
    fn classify_tx_ignores_wrong_deposit_idx_fulfillment() {
        let cfg = test_deposit_sm_cfg();
        let sm = create_sm(assigned_state());

        let data = WithdrawalFulfillmentData {
            deposit_idx: TEST_DEPOSIT_IDX + 1,
            withdrawal_funds: vec![OutPoint::default()],
            input_amount: Amount::from_sat(10_000_000),
            change_output: None,
            magic_bytes: TEST_MAGIC_BYTES.into(),
        };
        let wrong_fulfillment =
            WithdrawalFulfillmentTx::new(data, random_p2tr_desc()).into_unsigned_tx();

        let result = sm.classify_tx(&cfg, &wrong_fulfillment, LATER_BLOCK_HEIGHT);
        assert!(
            result.is_none(),
            "expected None for wrong deposit_idx but got {:?}",
            result
        );
    }

    #[test]
    fn classify_tx_ignores_non_spending_tx_in_payout_states() {
        let cfg = test_deposit_sm_cfg();
        let random_outpoint = OutPoint {
            txid: generate_txid(),
            vout: 0,
        };
        let non_spending_tx = generate_spending_tx(random_outpoint, &[]);

        for state in payout_pending_states() {
            let sm = create_sm(state);
            let result = sm.classify_tx(&cfg, &non_spending_tx, LATER_BLOCK_HEIGHT);
            assert!(result.is_none(), "expected None but got {:?}", result);
        }
    }
}
