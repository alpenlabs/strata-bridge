//! Pinning tests for [`DepositState`]'s persisted encoding.
#[cfg(test)]
mod tests {
    use crate::deposit::{state::DepositState, tests::*};

    /// A failure here means the enum was reordered, which needs a database migration rather
    /// than a recompile.
    #[test]
    fn deposit_state_variant_indices_are_stable() {
        let desc = random_p2tr_desc();

        let cases: [(u8, DepositState); 14] = [
            (
                0,
                DepositState::Created {
                    deposit_transaction: test_deposit_txn(),
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    claim_txids: BTreeMap::new(),
                },
            ),
            (
                1,
                DepositState::GraphGenerated {
                    deposit_transaction: test_deposit_txn(),
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    claim_txids: BTreeMap::new(),
                    pubnonces: BTreeMap::new(),
                },
            ),
            (
                2,
                DepositState::DepositNoncesCollected {
                    deposit_transaction: test_deposit_txn(),
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    claim_txids: BTreeMap::new(),
                    agg_nonce: generate_agg_nonce(),
                    pubnonces: BTreeMap::new(),
                    partial_signatures: BTreeMap::new(),
                },
            ),
            (
                3,
                DepositState::DepositPartialsCollected {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    deposit_transaction: test_deposit_txn().as_ref().clone(),
                },
            ),
            (
                4,
                DepositState::Deposited {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                },
            ),
            (
                5,
                DepositState::Assigned {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_ASSIGNEE,
                    deadline: LATER_BLOCK_HEIGHT,
                    recipient_desc: desc.clone(),
                },
            ),
            (
                6,
                DepositState::Fulfilled {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_ASSIGNEE,
                    fulfillment_txid: generate_txid(),
                    fulfillment_height: INITIAL_BLOCK_HEIGHT,
                    cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
                },
            ),
            (
                7,
                DepositState::PayoutDescriptorReceived {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_ASSIGNEE,
                    fulfillment_txid: generate_txid(),
                    cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                    cooperative_payout_tx: test_cooperative_payout_txn(desc.clone()),
                    payout_nonces: BTreeMap::new(),
                },
            ),
            (
                8,
                DepositState::PayoutNoncesCollected {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_ASSIGNEE,
                    fulfillment_txid: generate_txid(),
                    cooperative_payout_tx: test_cooperative_payout_txn(desc.clone()),
                    cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
                    payout_nonces: BTreeMap::new(),
                    payout_aggregated_nonce: generate_agg_nonce(),
                    payout_partial_signatures: BTreeMap::new(),
                },
            ),
            (
                9,
                DepositState::CooperativePathFailed {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    assignee: TEST_ASSIGNEE,
                    fulfillment_txid: generate_txid(),
                },
            ),
            (
                10,
                DepositState::Spent {
                    fulfillment_txid: None,
                    assignee: None,
                },
            ),
            (11, DepositState::Aborted),
            (
                12,
                DepositState::SweepNoncesPending {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    sweep_tx: test_sweep_txn(desc.clone()),
                    sweep_nonces: BTreeMap::new(),
                },
            ),
            (
                13,
                DepositState::SweepNoncesCollected {
                    last_block_height: INITIAL_BLOCK_HEIGHT,
                    sweep_tx: test_sweep_txn(desc.clone()),
                    sweep_agg_nonce: generate_agg_nonce(),
                    sweep_nonces: BTreeMap::new(),
                    sweep_partials: BTreeMap::new(),
                },
            ),
        ];

        for (expected_index, state) in cases {
            let encoded = postcard::to_allocvec(&state).expect("state must serialize");
            assert_eq!(
                encoded.first().copied(),
                Some(expected_index),
                "{state} must encode as variant index {expected_index}"
            );
        }
    }
}
