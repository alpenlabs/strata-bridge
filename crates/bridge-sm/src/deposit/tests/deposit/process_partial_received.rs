//! Unit Tests for process_partial_received
#[cfg(test)]
mod tests {
    use musig2::{AggNonce, PubNonce};

    use crate::{
        deposit::{
            duties::DepositDuty,
            errors::DSMError,
            events::{DepositEvent, PartialReceivedEvent},
            machine::DepositSM,
            state::DepositState,
            tests::*,
        },
        testing::transition::*,
    };

    #[test]
    fn test_process_partial_sequence() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
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
        let agg_nonce = AggNonce::sum(pubnonces.values().cloned());

        let initial_state = DepositState::DepositNoncesCollected {
            deposit_transaction: deposit_tx.clone(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces,
            agg_nonce: agg_nonce.clone(),
            partial_signatures: BTreeMap::new(),
        };

        let sm = create_sm(initial_state);
        let mut seq = EventSequence::new(sm, get_state);

        for signer in &operator_signers {
            let partial_sig = signer.sign(
                &key_agg_ctx,
                operator_signers_nonce_counter,
                &agg_nonce,
                sighash,
            );
            seq.process(
                &test_bridge_cfg(),
                DepositEvent::PartialReceived(PartialReceivedEvent {
                    partial_sig,
                    operator_idx: signer.operator_idx(),
                }),
            );
        }

        seq.assert_no_errors();

        // Should transition to DepositPartialsCollected
        assert!(matches!(
            seq.state(),
            DepositState::DepositPartialsCollected { .. }
        ));

        // Check that a PublishDeposit duty was emitted
        assert!(
            matches!(
                seq.all_duties().as_slice(),
                [DepositDuty::PublishDeposit { .. }]
            ),
            "Expected exactly 1 PublishDeposit duty to be emitted"
        );
    }

    #[test]
    fn test_invalid_process_partial_sequence() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let mut operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
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
        let agg_nonce = AggNonce::sum(pubnonces.values().cloned());

        let initial_state = DepositState::DepositNoncesCollected {
            deposit_transaction: deposit_tx.clone(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces,
            agg_nonce: agg_nonce.clone(),
            partial_signatures: BTreeMap::new(),
        };

        let sm = create_sm(initial_state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        // Update the nonce counter to simulate invalid signature
        operator_signers_nonce_counter += 1;

        for signer in &operator_signers {
            let partial_sig = signer.sign(
                &key_agg_ctx,
                operator_signers_nonce_counter,
                &agg_nonce,
                sighash,
            );
            seq.process(
                &test_bridge_cfg(),
                DepositEvent::PartialReceived(PartialReceivedEvent {
                    partial_sig,
                    operator_idx: signer.operator_idx(),
                }),
            );
        }

        // Shoudon't have transitioned state
        seq.assert_final_state(&initial_state);

        // Should have errors due to invalid partial signatures
        let errors = seq.all_errors();
        assert_eq!(
            errors.len(),
            operator_signers.len(),
            "Expected {} errors for invalid partial signatures, got {}",
            operator_signers.len(),
            errors.len()
        );
        errors.iter().for_each(|err| {
            assert!(
                matches!(err, DSMError::Rejected { .. }),
                "Expected Rejected error, got {:?}",
                err
            );
        });
    }

    #[test]
    fn test_duplicate_process_partial_sequence() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
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
        let agg_nonce = AggNonce::sum(pubnonces.values().cloned());

        let initial_state = DepositState::DepositNoncesCollected {
            deposit_transaction: deposit_tx.clone(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces,
            agg_nonce: agg_nonce.clone(),
            partial_signatures: BTreeMap::new(),
        };

        let sm = create_sm(initial_state.clone());
        let mut seq = EventSequence::new(sm, get_state);

        // Process partial signatures, all operators except the last one
        for signer in operator_signers
            .iter()
            .take(operator_signers.len().saturating_sub(1))
        {
            let partial_sig = signer.sign(
                &key_agg_ctx,
                operator_signers_nonce_counter,
                &agg_nonce,
                sighash,
            );
            let event = DepositEvent::PartialReceived(PartialReceivedEvent {
                partial_sig,
                operator_idx: signer.operator_idx(),
            });
            seq.process(&test_bridge_cfg(), event.clone());

            // Process the same event again to simulate duplicate
            test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
                create_sm,
                &test_bridge_cfg(),
                InvalidTransition {
                    from_state: seq.state().clone(),
                    event,
                    expected_error: |e| matches!(e, DSMError::Duplicate { .. }),
                },
            );
        }
    }

    #[test]
    fn test_invalid_operator_idx_in_process_partial() {
        let deposit_tx = test_deposit_txn();
        let operator_signers = test_operator_signers();
        let operator_signers_nonce_counter = 0u64;

        // Extract signing info
        let (key_agg_ctx, sighash) = get_deposit_signing_info(&deposit_tx, &operator_signers);
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
        let agg_nonce = AggNonce::sum(pubnonces.values().cloned());

        let initial_state = DepositState::DepositNoncesCollected {
            deposit_transaction: deposit_tx.clone(),
            last_block_height: INITIAL_BLOCK_HEIGHT,
            pubnonces,
            agg_nonce: agg_nonce.clone(),
            partial_signatures: BTreeMap::new(),
        };

        // Process partial signatures, with invalid operator idx
        let signer = operator_signers.first().expect("singer set empty");
        let partial_sig = signer.sign(
            &key_agg_ctx,
            operator_signers_nonce_counter,
            &agg_nonce,
            sighash,
        );
        let event = DepositEvent::PartialReceived(PartialReceivedEvent {
            partial_sig,
            operator_idx: u32::MAX,
        });

        test_invalid_transition::<DepositSM, _, _, _, _, _, _>(
            create_sm,
            &test_bridge_cfg(),
            InvalidTransition {
                from_state: initial_state,
                event,
                expected_error: |e| matches!(e, DSMError::Rejected { .. }),
            },
        );
    }
}
