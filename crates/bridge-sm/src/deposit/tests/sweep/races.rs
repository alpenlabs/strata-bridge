//! SM-level race resolution between the sweep and an in-flight withdrawal: whichever
//! transaction spends the deposit outpoint first, every ordering converges to `Spent`.
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use musig2::{AggNonce, aggregate_partial_signatures};

    use crate::{
        deposit::{
            duties::DepositDuty,
            events::{
                DepositEvent, PayoutConfirmedEvent, SweepNonceReceivedEvent,
                SweepPartialReceivedEvent, SweepRequestedEvent,
            },
            state::DepositState,
            tests::*,
        },
        testing::transition::EventSequence,
    };

    /// A `PayoutNoncesCollected` state with a fully populated cooperative-payout session.
    fn mid_payout_state() -> DepositState {
        let nonces: BTreeMap<_, _> = (0..N_TEST_OPERATORS)
            .map(|idx| (idx as u32, generate_pubnonce()))
            .collect();
        let payout_aggregated_nonce = AggNonce::sum(nonces.values().cloned());

        DepositState::PayoutNoncesCollected {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            fulfillment_txid: generate_txid(),
            cooperative_payout_tx: test_cooperative_payout_txn(random_p2tr_desc()),
            cooperative_payment_deadline: LATER_BLOCK_HEIGHT,
            payout_nonces: nonces,
            payout_aggregated_nonce,
            payout_partial_signatures: BTreeMap::new(),
        }
    }

    /// Drives a full sweep round from `from_state`, finalizes the sweep transaction, confirms
    /// it, and asserts the deposit lands in `Spent` with no preserved withdrawal info (the
    /// sweep entry discarded it).
    fn assert_sweep_completes_from(from_state: DepositState) {
        let signers = test_operator_signers();
        let desc = random_p2tr_desc();
        let sweep_tx = test_sweep_txn(desc.clone());
        let (key_agg_ctx, message) = get_sweep_signing_info(&sweep_tx, &signers);
        let agg_pubkey = key_agg_ctx.aggregated_pubkey();
        let nonce_counter = 0u64;

        let sm = create_sm(from_state);
        let mut seq = EventSequence::new(sm, get_state);

        seq.process(
            test_deposit_sm_cfg(),
            DepositEvent::SweepRequested(SweepRequestedEvent {
                safe_harbour_desc: desc.clone(),
            }),
        );

        let nonces: BTreeMap<_, _> = signers
            .iter()
            .map(|s| (s.operator_idx(), s.pubnonce(agg_pubkey, nonce_counter)))
            .collect();
        for (operator_idx, sweep_nonce) in &nonces {
            seq.process(
                test_deposit_sm_cfg(),
                DepositEvent::SweepNonceReceived(SweepNonceReceivedEvent {
                    sweep_nonce: sweep_nonce.clone(),
                    operator_idx: *operator_idx,
                }),
            );
        }
        let agg_nonce = AggNonce::sum(nonces.values().cloned());

        for signer in &signers {
            let partial = signer.sign(&key_agg_ctx, nonce_counter, &agg_nonce, message);
            seq.process(
                test_deposit_sm_cfg(),
                DepositEvent::SweepPartialReceived(SweepPartialReceivedEvent {
                    partial_signature: partial,
                    operator_idx: signer.operator_idx(),
                }),
            );
        }

        seq.assert_no_errors();

        let duties = seq.all_duties();
        let (duty_agg_nonce, collected_partials, duty_sweep_tx) = duties
            .iter()
            .find_map(|duty| match duty {
                DepositDuty::PublishSweep {
                    agg_nonce,
                    collected_partials,
                    sweep_tx,
                    ..
                } => Some((agg_nonce, collected_partials, sweep_tx)),
                _ => None,
            })
            .expect("PublishSweep duty must be emitted");

        let ordered_partials: Vec<_> = collected_partials.values().copied().collect();
        let agg_signature = aggregate_partial_signatures(
            &key_agg_ctx,
            duty_agg_nonce,
            ordered_partials,
            message.as_ref(),
        )
        .expect("aggregated sweep signature must verify");
        let finalized = (**duty_sweep_tx).clone().finalize(agg_signature);

        seq.process(
            test_deposit_sm_cfg(),
            DepositEvent::PayoutConfirmed(PayoutConfirmedEvent { tx: finalized }),
        );
        seq.assert_no_errors()
            .assert_final_state(&DepositState::Spent {
                fulfillment_txid: None,
                assignee: None,
            });
    }

    /// Sweep-wins race: entering the sweep mid-payout abandons the in-flight cooperative-payout
    /// session, and the full symmetric signing round completes exactly as from `Deposited`.
    #[test]
    fn test_sweep_wins_race_from_mid_payout_states() {
        assert_sweep_completes_from(mid_payout_state());
        assert_sweep_completes_from(DepositState::Fulfilled {
            last_block_height: INITIAL_BLOCK_HEIGHT,
            assignee: TEST_ASSIGNEE,
            fulfillment_txid: generate_txid(),
            fulfillment_height: INITIAL_BLOCK_HEIGHT,
            cooperative_payout_deadline: LATER_BLOCK_HEIGHT,
        });
    }

    /// Payout-wins race: the assignee finalizes the cooperative payout with the partials
    /// gossiped before the sweep started, and its confirmation terminates the sweep flow.
    #[test]
    fn test_payout_wins_race_after_sweep_entry() {
        let signers = test_operator_signers();
        let desc = random_p2tr_desc();

        let sm = create_sm(mid_payout_state());
        let mut seq = EventSequence::new(sm, get_state);

        // The sweep starts and collects one nonce, then the racing payout confirms.
        seq.process(
            test_deposit_sm_cfg(),
            DepositEvent::SweepRequested(SweepRequestedEvent {
                safe_harbour_desc: desc.clone(),
            }),
        );
        let sweep_tx = test_sweep_txn(desc);
        let (key_agg_ctx, _) = get_sweep_signing_info(&sweep_tx, &signers);
        seq.process(
            test_deposit_sm_cfg(),
            DepositEvent::SweepNonceReceived(SweepNonceReceivedEvent {
                sweep_nonce: signers[0].pubnonce(key_agg_ctx.aggregated_pubkey(), 0),
                operator_idx: signers[0].operator_idx(),
            }),
        );

        seq.process(
            test_deposit_sm_cfg(),
            DepositEvent::PayoutConfirmed(PayoutConfirmedEvent {
                tx: test_payout_tx(test_deposit_outpoint()),
            }),
        );

        // The payout won: terminal, with the withdrawal info already discarded at sweep entry.
        seq.assert_no_errors()
            .assert_final_state(&DepositState::Spent {
                fulfillment_txid: None,
                assignee: None,
            });
    }
}
