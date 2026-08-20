//! Unit tests for the DepositDuty safe-harbour suppression taxonomy.
#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use crate::deposit::{duties::NagDuty, tests::*};

    fn nag_duties() -> Vec<(NagDuty, bool)> {
        let operator_pubkey = test_operator_table(N_TEST_OPERATORS, TEST_POV_IDX)
            .idx_to_p2p_key(&TEST_ASSIGNEE)
            .expect("assignee must be in the operator table")
            .clone();

        vec![
            (
                NagDuty::NagDepositNonce {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    operator_idx: TEST_ASSIGNEE,
                    operator_pubkey: operator_pubkey.clone(),
                },
                false,
            ),
            (
                NagDuty::NagDepositPartial {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    operator_idx: TEST_ASSIGNEE,
                    operator_pubkey: operator_pubkey.clone(),
                },
                false,
            ),
            (
                NagDuty::NagPayoutNonce {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    operator_idx: TEST_ASSIGNEE,
                    operator_pubkey: operator_pubkey.clone(),
                },
                true,
            ),
            (
                NagDuty::NagPayoutPartial {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    operator_idx: TEST_ASSIGNEE,
                    operator_pubkey: operator_pubkey.clone(),
                },
                true,
            ),
            (
                NagDuty::NagSweepNonce {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    operator_idx: TEST_ASSIGNEE,
                    operator_pubkey: operator_pubkey.clone(),
                },
                false,
            ),
            (
                NagDuty::NagSweepPartial {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    operator_idx: TEST_ASSIGNEE,
                    operator_pubkey,
                },
                false,
            ),
        ]
    }

    /// Pins the safe-harbour suppression classification of every deposit duty: only the duties that
    /// front a user or advance the cooperative payout are suppressible under safe harbour.
    #[test]
    fn test_should_suppress_under_safe_harbour_per_deposit_duty() {
        let desc = random_p2tr_desc();
        let sweep_tx = test_sweep_txn(desc.clone());
        let sighash = sweep_tx.signing_info()[0].sighash;
        let deposit_signing_info = test_deposit_txn()
            .signing_info()
            .into_iter()
            .next()
            .expect("deposit transaction must have signing info");

        let cases = vec![
            (
                DepositDuty::PublishDepositNonce {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    drt_outpoint: OutPoint::default(),
                    claim_txids: vec![],
                    ordered_pubkeys: vec![],
                    drt_tweak: TaprootTweak::Key { tweak: None },
                    sighash,
                },
                false,
            ),
            (
                DepositDuty::PublishDepositPartial {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    drt_outpoint: OutPoint::default(),
                    claim_txids: vec![],
                    signing_info: deposit_signing_info,
                    deposit_agg_nonce: generate_agg_nonce(),
                    ordered_pubkeys: vec![],
                },
                false,
            ),
            (
                DepositDuty::PublishDeposit {
                    signed_deposit_transaction: test_deposit_txn().as_ref().clone(),
                },
                false,
            ),
            (
                DepositDuty::FulfillWithdrawalRequest {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    deadline: LATER_BLOCK_HEIGHT,
                    recipient_desc: desc.clone(),
                    deposit_amount: TEST_DEPOSIT_AMOUNT,
                },
                true,
            ),
            (
                DepositDuty::RequestPayoutNonces {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    pov_operator_idx: TEST_POV_IDX,
                    payout_descriptor: None,
                },
                true,
            ),
            (
                DepositDuty::PublishPayoutNonce {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    deposit_outpoint: test_deposit_outpoint(),
                    ordered_pubkeys: vec![],
                    tweak: TaprootTweak::Key { tweak: None },
                    payout_sighash: sighash,
                },
                true,
            ),
            (
                DepositDuty::PublishPayoutPartial {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    deposit_outpoint: test_deposit_outpoint(),
                    payout_sighash: sighash,
                    agg_nonce: generate_agg_nonce(),
                    ordered_pubkeys: vec![],
                },
                true,
            ),
            (
                DepositDuty::PublishPayout {
                    deposit_outpoint: test_deposit_outpoint(),
                    agg_nonce: generate_agg_nonce(),
                    collected_partials: BTreeMap::new(),
                    payout_coop_tx: Box::new(test_cooperative_payout_txn(desc.clone())),
                    ordered_pubkeys: vec![],
                    pov_operator_idx: TEST_POV_IDX,
                },
                true,
            ),
            (
                DepositDuty::PublishSweepNonce {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    deposit_outpoint: test_deposit_outpoint(),
                    ordered_pubkeys: vec![],
                    tweak: TaprootTweak::Key { tweak: None },
                    sweep_sighash: sighash,
                },
                false,
            ),
            (
                DepositDuty::PublishSweepPartial {
                    deposit_idx: TEST_DEPOSIT_IDX,
                    deposit_outpoint: test_deposit_outpoint(),
                    sweep_sighash: sighash,
                    agg_nonce: generate_agg_nonce(),
                    ordered_pubkeys: vec![],
                },
                false,
            ),
            (
                DepositDuty::PublishSweep {
                    deposit_outpoint: test_deposit_outpoint(),
                    agg_nonce: generate_agg_nonce(),
                    collected_partials: BTreeMap::new(),
                    sweep_tx: Box::new(sweep_tx),
                    ordered_pubkeys: vec![],
                },
                false,
            ),
        ];

        for (duty, expected) in cases {
            assert_eq!(
                duty.should_suppress_under_safe_harbour(),
                expected,
                "unexpected safe-harbour suppression for {duty}"
            );
        }
    }

    /// Pins the safe-harbour suppression classification of every nag duty, directly and wrapped in
    /// [`DepositDuty::Nag`]: only the payout-session nags solicit withdrawal progress.
    #[test]
    fn test_should_suppress_under_safe_harbour_per_nag_duty() {
        for (nag, expected) in nag_duties() {
            assert_eq!(
                nag.should_suppress_under_safe_harbour(),
                expected,
                "unexpected safe-harbour suppression for {nag}"
            );
            let duty = DepositDuty::Nag { duty: nag };
            assert_eq!(
                duty.should_suppress_under_safe_harbour(),
                expected,
                "unexpected safe-harbour suppression for {duty}"
            );
        }
    }
}
