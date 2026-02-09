//! Unit Tests for process_nonce_received
#[cfg(test)]
mod tests {
    use musig2::PubNonce;

    use crate::{
        deposit::{
            duties::DepositDuty,
            errors::DSMError,
            events::{DepositEvent, NonceReceivedEvent},
            state::DepositState,
            tests::*,
        },
        testing::transition::*,
    };

    #[test]
    fn test_process_nonce_sequence() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, _sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
        let tweaked_agg_pubkey = key_agg_ctx.aggregated_pubkey();

        // Generate nonces using the tweaked aggregated pubkey
        let pubnonces: BTreeMap<u32, PubNonce> = operator_signers
            .iter()
            .enumerate()
            .map(|(operatoridx, s)| {
                (
                    operatoridx as u32,
                    s.pubnonce(tweaked_agg_pubkey, operator_signers_nonce_counter),
                )
            })
            .collect();

        let initial_state = DepositState::GraphGenerated {
            deposit_transaction: deposit_tx.clone(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces: BTreeMap::new(),
        };

        let sm = create_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        for (operator_idx, nonce) in &pubnonces {
            seq.process(
                test_deposit_sm_cfg(),
                DepositEvent::NonceReceived(NonceReceivedEvent {
                    nonce: nonce.clone(),
                    operator_idx: *operator_idx,
                }),
            );
        }

        seq.assert_no_errors();

        // Should transition to DepositNoncesCollected
        assert!(matches!(
            seq.state(),
            DepositState::DepositNoncesCollected { .. }
        ));

        // Check that a PublishDepositPartial duty was emitted
        assert!(
            matches!(
                seq.all_duties().as_slice(),
                [DepositDuty::PublishDepositPartial { .. }]
            ),
            "Expected exactly 1 PublishDepositPartial duty to be emitted"
        );
    }

    #[test]
    fn test_duplicate_process_nonce_sequence() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, _sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
        let tweaked_agg_pubkey = key_agg_ctx.aggregated_pubkey();

        let initial_state = DepositState::GraphGenerated {
            deposit_transaction: deposit_tx.clone(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces: BTreeMap::new(),
        };

        let sm = create_sm(initial_state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        // Process nonces, all operators except the last one
        for signer in operator_signers
            .iter()
            .take(operator_signers.len().saturating_sub(1))
        {
            let nonce = signer.pubnonce(tweaked_agg_pubkey, operator_signers_nonce_counter);
            let event = DepositEvent::NonceReceived(NonceReceivedEvent {
                nonce,
                operator_idx: signer.operator_idx(),
            });
            seq.process(test_deposit_sm_cfg(), event.clone());

            // Process the same event again to simulate duplicate
            test_deposit_invalid_transition(DepositInvalidTransition {
                from_state: seq.state().clone(),
                event,
                expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
            });
        }
    }

    #[test]
    fn test_invalid_operator_idx_in_process_nonce() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, _sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
        let tweaked_agg_pubkey = key_agg_ctx.aggregated_pubkey();

        let initial_state = DepositState::GraphGenerated {
            deposit_transaction: deposit_tx.clone(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces: BTreeMap::new(),
        };

        // Process nonces, with invalid operator idex
        let signer = operator_signers.first().expect("singer set empty");
        let nonce = signer.pubnonce(tweaked_agg_pubkey, operator_signers_nonce_counter);
        let event = DepositEvent::NonceReceived(NonceReceivedEvent {
            nonce,
            operator_idx: u32::MAX,
        });

        test_deposit_invalid_transition(DepositInvalidTransition {
            from_state: initial_state,
            event,
            expected_error: |e| matches!(e, DSMError::Rejected { .. }),
        });
    }
}
