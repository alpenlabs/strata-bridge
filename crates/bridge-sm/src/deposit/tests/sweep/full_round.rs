//! End-to-end test of the symmetric sweep signing round.
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use musig2::{AggNonce, aggregate_partial_signatures};
    use strata_bridge_tx_graph::fee::sweep_payout_value;

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
        testing::{fixtures::TEST_SWEEP_FEE_RATE, transition::EventSequence},
    };

    /// Drives a full sweep round from `Deposited` through nonce and partial collection, then
    /// proves the emitted [`DepositDuty::PublishSweep`] aggregates into a valid signature and
    /// finalizes into the expected transaction.
    #[test]
    fn test_full_symmetric_sweep_round() {
        let signers = test_operator_signers();
        let desc = random_p2tr_desc();
        let sweep_tx = test_sweep_txn(desc.clone());
        let (key_agg_ctx, message) = get_sweep_signing_info(&sweep_tx, &signers);
        let agg_pubkey = key_agg_ctx.aggregated_pubkey();
        let nonce_counter = 0u64;

        let sm = create_sm(DepositState::Deposited {
            last_block_height: INITIAL_BLOCK_HEIGHT,
        });
        let mut seq = EventSequence::new(sm, get_state);

        // Seed the sweep with the injected safe-harbour descriptor.
        seq.process(
            test_deposit_sm_cfg(),
            DepositEvent::SweepRequested(SweepRequestedEvent {
                safe_harbour_desc: desc.clone(),
            }),
        );

        // Every operator's nonce arrives (own nonce loops back via ouroboros in production).
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

        // Every operator's partial arrives - the round is symmetric, none is withheld.
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

        // The final partial must trigger the PublishSweep duty with all N partials.
        let duties = seq.all_duties();
        let publish_sweep = duties
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
        let (duty_agg_nonce, collected_partials, duty_sweep_tx) = publish_sweep;
        assert_eq!(collected_partials.len(), N_TEST_OPERATORS);

        // The collected partials aggregate into a valid signature (aggregation verifies the
        // final signature against the aggregated key internally).
        let ordered_partials: Vec<_> = collected_partials.values().copied().collect();
        let agg_signature = aggregate_partial_signatures(
            &key_agg_ctx,
            duty_agg_nonce,
            ordered_partials,
            message.as_ref(),
        )
        .expect("aggregated sweep signature must verify");

        // The finalized transaction spends the deposit and pays the safe-harbour descriptor.
        let finalized = (**duty_sweep_tx).clone().finalize(agg_signature);
        assert_eq!(
            finalized.input[0].previous_output,
            test_deposit_outpoint(),
            "sweep must spend the deposit outpoint"
        );
        assert_eq!(
            finalized.output[0].script_pubkey,
            desc.to_script(),
            "sweep must pay the safe-harbour descriptor"
        );
        assert_eq!(
            finalized.output[0].value,
            sweep_payout_value(TEST_SWEEP_FEE_RATE, TEST_DEPOSIT_AMOUNT)
                .expect("test sweep fee rate must be valid"),
            "sweep must pay the deposit minus fee and anchor"
        );

        // Observing the sweep confirm on chain lands the deposit in Spent.
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
}
