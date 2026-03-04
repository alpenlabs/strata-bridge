//! Unit tests for process_nag_tick.
#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use musig2::AggNonce;

    use crate::{
        deposit::{
            duties::{DepositDuty, NagDuty},
            events::{DepositEvent, NagTickEvent},
            state::DepositState,
            tests::*,
        },
        testing::fixtures::test_operator_table,
    };

    // ===== GraphGenerated state tests (NagDepositNonce) =====

    #[test]
    fn test_nag_tick_emits_nag_deposit_nonce_for_missing_operators_in_graph_generated() {
        // Only one operator has submitted their nonce
        let mut pubnonces = BTreeMap::new();
        pubnonces.insert(TEST_ARBITRARY_OPERATOR_IDX, generate_pubnonce());

        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let expected = operator_table.operator_idxs();
        let present: BTreeSet<_> = pubnonces.keys().copied().collect();
        let expected_duties: Vec<DepositDuty> = expected
            .difference(&present)
            .map(|&op_idx| {
                let operator_pubkey = operator_table.idx_to_p2p_key(&op_idx).unwrap().clone();
                DepositDuty::Nag {
                    duty: NagDuty::NagDepositNonce {
                        deposit_idx: TEST_DEPOSIT_IDX,
                        operator_idx: op_idx,
                        operator_pubkey,
                    },
                }
            })
            .collect();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
                pubnonces,
            },
            event: DepositEvent::NagTick(NagTickEvent),
            expected_duties,
        });
    }

    #[test]
    fn test_nag_tick_emits_all_nag_deposit_nonce_when_none_present_in_graph_generated() {
        // No operators have submitted yet
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let expected = operator_table.operator_idxs();
        let present: BTreeSet<u32> = BTreeSet::new();
        let expected_duties: Vec<DepositDuty> = expected
            .difference(&present)
            .map(|&op_idx| {
                let operator_pubkey = operator_table.idx_to_p2p_key(&op_idx).unwrap().clone();
                DepositDuty::Nag {
                    duty: NagDuty::NagDepositNonce {
                        deposit_idx: TEST_DEPOSIT_IDX,
                        operator_idx: op_idx,
                        operator_pubkey,
                    },
                }
            })
            .collect();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
                pubnonces: BTreeMap::new(),
            },
            event: DepositEvent::NagTick(NagTickEvent),
            expected_duties,
        });
    }

    #[test]
    fn test_nag_tick_noop_when_all_present_in_graph_generated() {
        // All operators have submitted
        let expected = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX).operator_idxs();
        let pubnonces: BTreeMap<_, _> = expected
            .iter()
            .map(|&idx| (idx, generate_pubnonce()))
            .collect();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::GraphGenerated {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
                pubnonces,
            },
            event: DepositEvent::NagTick(NagTickEvent),
            expected_duties: vec![],
        });
    }

    // ===== DepositNoncesCollected state tests (NagDepositPartial) =====

    #[test]
    fn test_nag_tick_emits_nag_deposit_partial_for_missing_operators() {
        // Only one operator has submitted their partial
        let mut partial_signatures = BTreeMap::new();
        partial_signatures.insert(TEST_ARBITRARY_OPERATOR_IDX, generate_partial_signature());

        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let expected = operator_table.operator_idxs();
        let present: BTreeSet<_> = partial_signatures.keys().copied().collect();
        let expected_duties: Vec<DepositDuty> = expected
            .difference(&present)
            .map(|&op_idx| {
                let operator_pubkey = operator_table.idx_to_p2p_key(&op_idx).unwrap().clone();
                DepositDuty::Nag {
                    duty: NagDuty::NagDepositPartial {
                        deposit_idx: TEST_DEPOSIT_IDX,
                        operator_idx: op_idx,
                        operator_pubkey,
                    },
                }
            })
            .collect();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::DepositNoncesCollected {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
                agg_nonce: AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce())),
                pubnonces: BTreeMap::new(),
                partial_signatures,
            },
            event: DepositEvent::NagTick(NagTickEvent),
            expected_duties,
        });
    }

    #[test]
    fn test_nag_tick_emits_all_nag_deposit_partial_when_none_present() {
        // No operators have submitted yet
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let expected = operator_table.operator_idxs();
        let present: BTreeSet<u32> = BTreeSet::new();
        let expected_duties: Vec<DepositDuty> = expected
            .difference(&present)
            .map(|&op_idx| {
                let operator_pubkey = operator_table.idx_to_p2p_key(&op_idx).unwrap().clone();
                DepositDuty::Nag {
                    duty: NagDuty::NagDepositPartial {
                        deposit_idx: TEST_DEPOSIT_IDX,
                        operator_idx: op_idx,
                        operator_pubkey,
                    },
                }
            })
            .collect();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::DepositNoncesCollected {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
                agg_nonce: AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce())),
                pubnonces: BTreeMap::new(),
                partial_signatures: BTreeMap::new(),
            },
            event: DepositEvent::NagTick(NagTickEvent),
            expected_duties,
        });
    }

    #[test]
    fn test_nag_tick_noop_when_all_deposit_partials_collected() {
        // All operators have submitted
        let expected = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX).operator_idxs();
        let partial_signatures: BTreeMap<_, _> = expected
            .iter()
            .map(|&idx| (idx, generate_partial_signature()))
            .collect();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::DepositNoncesCollected {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
                agg_nonce: AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce())),
                pubnonces: BTreeMap::new(),
                partial_signatures,
            },
            event: DepositEvent::NagTick(NagTickEvent),
            expected_duties: vec![],
        });
    }

    // ===== PayoutDescriptorReceived state tests (NagPayoutNonce) =====

    #[test]
    fn test_nag_tick_emits_nag_payout_nonce_for_missing_operators() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc);

        // Only one operator has submitted payout nonce
        let mut payout_nonces = BTreeMap::new();
        payout_nonces.insert(TEST_ARBITRARY_OPERATOR_IDX, generate_pubnonce());

        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let expected = operator_table.operator_idxs();
        let present: BTreeSet<_> = payout_nonces.keys().copied().collect();
        let expected_duties: Vec<DepositDuty> = expected
            .difference(&present)
            .map(|&op_idx| {
                let operator_pubkey = operator_table.idx_to_p2p_key(&op_idx).unwrap().clone();
                DepositDuty::Nag {
                    duty: NagDuty::NagPayoutNonce {
                        deposit_idx: TEST_DEPOSIT_IDX,
                        operator_idx: op_idx,
                        operator_pubkey,
                    },
                }
            })
            .collect();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                cooperative_payout_tx,
                payout_nonces,
            },
            event: DepositEvent::NagTick(NagTickEvent),
            expected_duties,
        });
    }

    #[test]
    fn test_nag_tick_emits_all_nag_payout_nonce_when_none_present() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc);

        // No operators have submitted yet
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let expected = operator_table.operator_idxs();
        let present: BTreeSet<u32> = BTreeSet::new();
        let expected_duties: Vec<DepositDuty> = expected
            .difference(&present)
            .map(|&op_idx| {
                let operator_pubkey = operator_table.idx_to_p2p_key(&op_idx).unwrap().clone();
                DepositDuty::Nag {
                    duty: NagDuty::NagPayoutNonce {
                        deposit_idx: TEST_DEPOSIT_IDX,
                        operator_idx: op_idx,
                        operator_pubkey,
                    },
                }
            })
            .collect();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                cooperative_payout_tx,
                payout_nonces: BTreeMap::new(),
            },
            event: DepositEvent::NagTick(NagTickEvent),
            expected_duties,
        });
    }

    #[test]
    fn test_nag_tick_noop_when_all_payout_nonces_collected() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc);

        // All operators have submitted
        let expected = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX).operator_idxs();
        let payout_nonces: BTreeMap<_, _> = expected
            .iter()
            .map(|&idx| (idx, generate_pubnonce()))
            .collect();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::PayoutDescriptorReceived {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                cooperative_payout_tx,
                payout_nonces,
            },
            event: DepositEvent::NagTick(NagTickEvent),
            expected_duties: vec![],
        });
    }

    // ===== PayoutNoncesCollected state tests (NagPayoutPartial) =====

    #[test]
    fn test_nag_tick_emits_nag_payout_partial_for_missing_operators() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc);
        let payout_aggregated_nonce =
            AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));

        // Only TEST_NON_ASSIGNEE_IDX has submitted partial.
        let mut payout_partial_signatures = BTreeMap::new();
        payout_partial_signatures.insert(TEST_NON_ASSIGNEE_IDX, generate_partial_signature());

        // Expected excludes assignee; missing = expected - present
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let mut expected = operator_table.operator_idxs();
        expected.remove(&TEST_ASSIGNEE);
        let present: BTreeSet<_> = payout_partial_signatures.keys().copied().collect();
        let expected_duties: Vec<DepositDuty> = expected
            .difference(&present)
            .map(|&op_idx| {
                let operator_pubkey = operator_table.idx_to_p2p_key(&op_idx).unwrap().clone();
                DepositDuty::Nag {
                    duty: NagDuty::NagPayoutPartial {
                        deposit_idx: TEST_DEPOSIT_IDX,
                        operator_idx: op_idx,
                        operator_pubkey,
                    },
                }
            })
            .collect();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce,
                payout_partial_signatures,
            },
            event: DepositEvent::NagTick(NagTickEvent),
            expected_duties,
        });
    }

    #[test]
    fn test_nag_tick_excludes_assignee_from_payout_partial_nag() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc);
        let payout_aggregated_nonce =
            AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));

        // No partials submitted yet.
        // Expected nags: expected - present (where expected already excludes assignee)
        let operator_table = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX);
        let mut expected = operator_table.operator_idxs();
        expected.remove(&TEST_ASSIGNEE);
        let present: BTreeSet<u32> = BTreeSet::new();
        let expected_duties: Vec<DepositDuty> = expected
            .difference(&present)
            .map(|&op_idx| {
                let operator_pubkey = operator_table.idx_to_p2p_key(&op_idx).unwrap().clone();
                DepositDuty::Nag {
                    duty: NagDuty::NagPayoutPartial {
                        deposit_idx: TEST_DEPOSIT_IDX,
                        operator_idx: op_idx,
                        operator_pubkey,
                    },
                }
            })
            .collect();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce,
                payout_partial_signatures: BTreeMap::new(),
            },
            event: DepositEvent::NagTick(NagTickEvent),
            expected_duties,
        });
    }

    #[test]
    fn test_nag_tick_noop_when_all_non_assignee_partials_collected() {
        let operator_desc = random_p2tr_desc();
        let cooperative_payout_tx = test_cooperative_payout_txn(operator_desc);
        let payout_aggregated_nonce =
            AggNonce::sum((0..N_TEST_OPERATORS).map(|_| generate_pubnonce()));

        // All expected operators have submitted partials.
        let mut expected = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX).operator_idxs();
        expected.remove(&TEST_ASSIGNEE);
        let payout_partial_signatures: BTreeMap<_, _> = expected
            .iter()
            .map(|&idx| (idx, generate_partial_signature()))
            .collect();

        test_handler_output(DepositHandlerOutput {
            state: DepositState::PayoutNoncesCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_ASSIGNEE,
                cooperative_payout_tx,
                cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                payout_nonces: BTreeMap::new(),
                payout_aggregated_nonce,
                payout_partial_signatures,
            },
            event: DepositEvent::NagTick(NagTickEvent),
            expected_duties: vec![],
        });
    }

    // ===== Non-naggable states (no duties emitted) =====

    #[test]
    fn test_nag_tick_noop_for_non_naggable_states() {
        let non_naggable_states = [
            DepositState::Created {
                deposit_transaction: test_deposit_txn(),
                last_block_height: INITIAL_BLOCK_HEIGHT,
                claim_txids: BTreeMap::new(),
            },
            DepositState::DepositPartialsCollected {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                deposit_transaction: test_deposit_txn().as_ref().clone(),
            },
            DepositState::Deposited {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Assigned {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX,
                deadline: LATER_BLOCK_HEIGHT,
                recipient_desc: random_p2tr_desc(),
            },
            DepositState::Fulfilled {
                last_block_height: INITIAL_BLOCK_HEIGHT,
                assignee: TEST_POV_IDX,
                fulfillment_txid: generate_txid(),
                fulfillment_height: INITIAL_BLOCK_HEIGHT,
                cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
            },
            DepositState::CooperativePathFailed {
                last_block_height: INITIAL_BLOCK_HEIGHT,
            },
            DepositState::Spent,
            DepositState::Aborted,
        ];

        for state in non_naggable_states {
            test_handler_output(DepositHandlerOutput {
                state,
                event: DepositEvent::NagTick(NagTickEvent),
                expected_duties: vec![],
            });
        }
    }
}
