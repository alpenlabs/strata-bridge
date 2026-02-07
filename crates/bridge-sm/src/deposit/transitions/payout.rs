use std::collections::BTreeMap;

use bitcoin::Txid;
use musig2::{AggNonce, verify_partial};
use strata_bridge_connectors2::n_of_n::NOfNConnector;
use strata_bridge_primitives::{
    key_agg::create_agg_ctx,
    scripts::prelude::{TaprootWitness, get_aggregated_pubkey},
};
use strata_bridge_tx_graph2::transactions::prelude::{CooperativePayoutData, CooperativePayoutTx};

use crate::{
    deposit::{
        config::DepositSMCfg,
        duties::DepositDuty,
        errors::{DSMError, DSMResult},
        events::{
            DepositEvent, FulfillmentConfirmedEvent, PayoutConfirmedEvent,
            PayoutDescriptorReceivedEvent, PayoutNonceReceivedEvent, PayoutPartialReceivedEvent,
            WithdrawalAssignedEvent,
        },
        machine::{DSMOutput, DepositSM},
        state::DepositState,
    },
    state_machine::SMOutput,
};

impl DepositSM {
    /// Processes the event assigning an operator to fulfill the withdrawal.
    ///
    /// Transitions to [`DepositState::Assigned`] and emits a
    /// [`DepositDuty::FulfillWithdrawal`] duty if the local operator is the assignee.
    pub(crate) fn process_assignment(
        &mut self,
        assignment: WithdrawalAssignedEvent,
    ) -> DSMResult<DSMOutput> {
        match self.state() {
            DepositState::Deposited { last_block_height }
            | DepositState::Assigned {
                last_block_height, ..
            } => {
                self.state = DepositState::Assigned {
                    last_block_height: *last_block_height,
                    assignee: assignment.assignee,
                    deadline: assignment.deadline,
                    recipient_desc: assignment.recipient_desc.clone(),
                };
                // Dispatch the duty to fulfill the assignment if the assignee is the pov operator,
                // otherwise no duties or signals need to be dispatched.
                if self.sm_params.operator_table().pov_idx() == assignment.assignee {
                    Ok(DSMOutput::with_duties(vec![
                        DepositDuty::FulfillWithdrawal {
                            deposit_idx: self.sm_params.deposit_idx(),
                            deadline: assignment.deadline,
                            recipient_desc: assignment.recipient_desc,
                        },
                    ]))
                } else {
                    Ok(DSMOutput::new())
                }
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: DepositEvent::WithdrawalAssigned(assignment).to_string(),
                reason: None,
            }),
        }
    }

    /// Processes the event where the withdrawal fulfillment transaction is published.
    ///
    /// Records the fulfillment transaction and transitions to [`DepositState::Fulfilled`].
    /// Emits a [`DepositDuty::RequestPayoutNonces`] duty if the local operator is the assignee.
    pub(crate) fn process_fulfillment(
        &mut self,
        cfg: &DepositSMCfg,
        fulfillment: FulfillmentConfirmedEvent,
    ) -> DSMResult<DSMOutput> {
        match self.state() {
            DepositState::Assigned {
                last_block_height,
                assignee,
                ..
            } => {
                let assignee = *assignee;
                let timeout = cfg.cooperative_payout_timeout_blocks();

                // Compute the txid of the fulfillment transaction
                let fulfillment_txid: Txid = fulfillment.fulfillment_transaction.compute_txid();

                // Compute the cooperative payout deadline.
                let cooperative_payment_deadline = fulfillment.fulfillment_height + timeout;

                // Transition to the Fulfilled state
                self.state = DepositState::Fulfilled {
                    last_block_height: *last_block_height,
                    assignee,
                    fulfillment_txid,
                    fulfillment_height: fulfillment.fulfillment_height,
                    cooperative_payout_deadline: cooperative_payment_deadline,
                };
                // Dispatch the duty to request the payout nonces if the assignee is the pov
                // operator, otherwise no duties or signals need to be dispatched.
                if self.sm_params.operator_table().pov_idx() == assignee {
                    Ok(DSMOutput::with_duties(vec![
                        DepositDuty::RequestPayoutNonces {
                            deposit_idx: self.sm_params.deposit_idx(),
                        },
                    ]))
                } else {
                    Ok(DSMOutput::new())
                }
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: DepositEvent::FulfillmentConfirmed(fulfillment).to_string(),
                reason: None,
            }),
        }
    }

    /// Processes the event where the assignee's payout descriptor is received.
    ///
    /// Transitions to [`DepositState::PayoutDescriptorReceived`] and emits a
    /// [`DepositDuty::PublishPayoutNonce`] duty.
    pub(crate) fn process_payout_descriptor_received(
        &mut self,
        descriptor: PayoutDescriptorReceivedEvent,
    ) -> DSMResult<DSMOutput> {
        match self.state() {
            DepositState::Fulfilled {
                last_block_height,
                assignee,
                cooperative_payout_deadline: cooperative_payment_deadline,
                ..
            } => {
                let assignee = *assignee;

                // Transition to the PayoutDescriptorReceived state
                self.state = DepositState::PayoutDescriptorReceived {
                    last_block_height: *last_block_height,
                    assignee,
                    cooperative_payment_deadline: *cooperative_payment_deadline,
                    operator_desc: descriptor.operator_desc.clone(),
                    payout_nonces: BTreeMap::new(),
                };
                // Dispatch the duty to publish the payout nonce
                Ok(DSMOutput::with_duties(vec![
                    DepositDuty::PublishPayoutNonce {
                        deposit_outpoint: self.sm_params.deposit_outpoint(),
                        operator_idx: assignee,
                        operator_desc: descriptor.operator_desc,
                    },
                ]))
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: DepositEvent::PayoutDescriptorReceived(descriptor).to_string(),
                reason: None,
            }),
        }
    }

    /// Processes the event where an operator's payout nonce is received.
    ///
    /// Collects payout nonces required for cooperative payout signing. Once all nonces
    /// are collected, transitions to [`DepositState::PayoutNoncesCollected`] and emits a
    /// [`DepositDuty::PublishPayoutPartial`] duty for non-assignee operators.
    pub(crate) fn process_payout_nonce_received(
        &mut self,
        payout_nonce: PayoutNonceReceivedEvent,
    ) -> DSMResult<DSMOutput> {
        // Validate operator_idx is in the operator table
        self.check_operator_idx(payout_nonce.operator_idx, &payout_nonce)?;

        let operator_table_cardinality = self.sm_params.operator_table().cardinality();
        let pov_operator_idx = self.sm_params.operator_table().pov_idx();

        match self.state_mut() {
            DepositState::PayoutDescriptorReceived {
                last_block_height,
                assignee,
                cooperative_payment_deadline,
                operator_desc,
                payout_nonces,
            } => {
                let assignee = *assignee;

                // Check for duplicate nonce submission. If an entry from the same operator exists,
                // return with an error.
                if payout_nonces.contains_key(&payout_nonce.operator_idx) {
                    return Err(DSMError::Duplicate {
                        state: self.state().to_string(),
                        event: payout_nonce.to_string(),
                    });
                }
                // Update the payout nonces with the new nonce just received.
                payout_nonces.insert(payout_nonce.operator_idx, payout_nonce.payout_nonce);

                // Transition to the PayoutNoncesCollected State if *all* the nonces have been
                // received. Dispatch duty to publish the cooperative payout partial signatures
                // unless the pov operator is the assignee.
                if operator_table_cardinality == payout_nonces.len() {
                    // Compute the aggregated nonce from the collected nonces.
                    let agg_nonce = AggNonce::sum(payout_nonces.values());

                    // Transition to the PayoutNoncesCollected State.
                    self.state = DepositState::PayoutNoncesCollected {
                        last_block_height: *last_block_height,
                        assignee,
                        operator_desc: operator_desc.clone(),
                        cooperative_payment_deadline: *cooperative_payment_deadline,
                        payout_nonces: payout_nonces.clone(),
                        payout_aggregated_nonce: agg_nonce.clone(),
                        payout_partial_signatures: BTreeMap::new(),
                    };

                    // Dispatch the duty to publish payout partial signature if the pov operator is
                    // NOT the assignee.
                    // The assignee should *NOT* publish their partial signature to prevent payout
                    // hostage attack. If the assignee published their partial, a malicious
                    // coordinator/operator could withhold their own partial and force the
                    // assignee to fall back to posting a claim. If a cooperative payout is later
                    // broadcast, the assignee is unable to spend the contested or uncontested path,
                    // and can be slashed after the timelock expires. By withholding their
                    // partial, only the assignee can finalize and broadcast
                    if pov_operator_idx != assignee {
                        Ok(DSMOutput::with_duties(vec![
                            DepositDuty::PublishPayoutPartial {
                                deposit_outpoint: self.sm_params.deposit_outpoint(),
                                deposit_idx: self.sm_params.deposit_idx(),
                                agg_nonce,
                            },
                        ]))
                    } else {
                        Ok(DSMOutput::new())
                    }
                }
                // If all nonces are not yet collected, stay in the PayoutDescriptorReceived State
                // and dispatch no duties or signals.
                else {
                    Ok(DSMOutput::new())
                }
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: DepositEvent::PayoutNonceReceived(payout_nonce).to_string(),
                reason: None,
            }),
        }
    }

    /// Processes the event where an operator's payout partial signature is received.
    ///
    /// Verifies and collects payout partial signatures. Once enough partials are collected
    /// (all except the assignee), emits a [`DepositDuty::PublishPayout`] duty if the local
    /// operator is the assignee.
    pub(crate) fn process_payout_partial_received(
        &mut self,
        cfg: &DepositSMCfg,
        payout_partial: PayoutPartialReceivedEvent,
    ) -> DSMResult<DSMOutput> {
        // Validate operator_idx is in the operator table
        self.check_operator_idx(payout_partial.operator_idx, &payout_partial)?;

        // Extract from self.cfg before the match to avoid borrow conflicts
        let operator_table_cardinality = self.sm_params.operator_table().cardinality();
        let pov_operator_idx = self.sm_params.operator_table().pov_idx();
        let n_of_n_pubkey = get_aggregated_pubkey(self.sm_params.operator_table().btc_keys());
        let deposit_connector =
            NOfNConnector::new(cfg.network(), n_of_n_pubkey, cfg.deposit_amount());
        let coop_payout_data = CooperativePayoutData {
            deposit_outpoint: self.sm_params.deposit_outpoint(),
        };
        // Generate the key_agg_ctx using the operator table.
        // NOfNConnector uses key-path spend with no script tree, so we use
        // TaprootWitness::Key which applies with_unspendable_taproot_tweak()
        let key_agg_ctx = create_agg_ctx(
            self.sm_params.operator_table().btc_keys(),
            &TaprootWitness::Key,
        )
        .expect("must be able to create key aggregation context");
        let operator_pubkey = self
            .sm_params
            .operator_table
            .idx_to_btc_key(&payout_partial.operator_idx)
            .expect("operator must be in table");

        match self.state_mut() {
            DepositState::PayoutNoncesCollected {
                assignee,
                operator_desc,
                payout_nonces,
                payout_aggregated_nonce,
                payout_partial_signatures,
                ..
            } => {
                let assignee = *assignee;

                // Check for duplicate Partial Signature submission. If an entry from the same
                // operator exists, return with an error.
                if payout_partial_signatures.contains_key(&payout_partial.operator_idx) {
                    return Err(DSMError::Duplicate {
                        state: self.state().to_string(),
                        event: payout_partial.to_string(),
                    });
                }

                // Construct the cooperative payout transaction.
                let coop_payout_tx = CooperativePayoutTx::new(
                    coop_payout_data,
                    deposit_connector,
                    operator_desc.clone(),
                );

                // Get the sighash for signature verification
                let signing_info = coop_payout_tx.signing_info();
                let message = signing_info[0].sighash;

                // Get the operator's pubnonce for verification.
                let operator_pubnonce = payout_nonces
                    .get(&payout_partial.operator_idx)
                    .expect("operator must have submitted nonce");

                // Verify the partial signature.
                if verify_partial(
                    &key_agg_ctx,
                    payout_partial.partial_signature,
                    payout_aggregated_nonce,
                    operator_pubkey,
                    operator_pubnonce,
                    message.as_ref(),
                )
                .is_err()
                {
                    return Err(DSMError::Rejected {
                        state: self.state().to_string(),
                        reason: "Partial Signature Verification Failed".to_string(),
                        event: payout_partial.to_string(),
                    });
                }

                // If the partial signature verification passes, add it to state
                payout_partial_signatures.insert(
                    payout_partial.operator_idx,
                    payout_partial.partial_signature,
                );

                // Check that *all* the partial signatures except from the assignee
                // for the cooperative payout have been received.
                // HACK: (mukeshdroid) The stricter check would have been to assert that the
                // partials except from the assignee has been collected. The following check that
                // asserts *any* n-1 partials are collected is enough since the assignee should
                // never send their partials for their own good.
                if operator_table_cardinality - 1 == payout_partial_signatures.len() {
                    // Dispatch the duty to publish payout tx if the pov operator is the assignee.
                    if pov_operator_idx == assignee {
                        Ok(DSMOutput::with_duties(vec![DepositDuty::PublishPayout {
                            payout_tx: coop_payout_tx.as_ref().clone(),
                        }]))
                    } else {
                        Ok(DSMOutput::new())
                    }
                } else {
                    // If there are remaining partial signatures (except the assignee),
                    // stay in same state.
                    Ok(DSMOutput::new())
                }
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: DepositEvent::PayoutPartialReceived(payout_partial).to_string(),
                reason: None,
            }),
        }
    }

    /// Processes the confirmation of a transaction that spends the deposit outpoint being tracked
    /// by this state machine.
    ///
    /// This outpoint can be spent via the following transactions:
    ///
    /// - A cooperative payout transaction, if the cooperative path was successful.
    /// - An uncontested payout transaction, if the assignee published a claim that went
    ///   uncontested.
    /// - A contested payout transaction, if the assignee published a claim that was contested but
    ///   not successfully.
    /// - A sweep transaction in the event of a hard upgrade (migration) of deposited UTXOs.
    pub(crate) fn process_payout_confirmed(
        &mut self,
        payout_confirmed: &PayoutConfirmedEvent,
    ) -> DSMResult<DSMOutput> {
        match self.state() {
            // It must be the sweep transaction in case of a hard upgrade
            DepositState::Deposited { .. }
            // It must be a cooperative payout transaction.
            // The assignee withholds their own partial and broadcasts the payout tx themselves,
            // In this case, we still want other nodes' state machines to transition from
            // `PayoutNoncesCollected` to `Spent`. This can also happen if there are network delays.
            | DepositState::PayoutNoncesCollected { .. }
            // It can be a contested/uncontested payout transaction
            // It can also be a cooperative payout transaction due to delayed settlement of the
            // transaction on-chain or because each operator has a different configuration for how
            // long to wait till the cooperative payout path is considered failed.
            | DepositState::CooperativePathFailed { .. } => {
                payout_confirmed.tx
                .input
                .iter()
                .any(|input| input.previous_output == self.sm_cfg().deposit_outpoint)
                .ok_or(DSMError::InvalidEvent {
                    state: self.state().to_string(),
                    event: DepositEvent::PayoutConfirmed(payout_confirmed.clone()).to_string(),
                    reason: format!(
                        "Transaction {} does not spend from the expected deposit outpoint {}",
                        payout_confirmed.tx.compute_txid(),
                        self.sm_cfg().deposit_outpoint
                        ).into(),
                })?;

                // Transition to Spent state
                self.state = DepositState::Spent;

                // This is a terminal state
                Ok(SMOutput {
                    duties: vec![],
                    signals: vec![],
                })
            }
            DepositState::Spent => Err(DSMError::Duplicate {
                state: self.state().to_string(),
                event: payout_confirmed.to_string(),
            }),
            _ => Err(DSMError::InvalidEvent {
                event: DepositEvent::PayoutConfirmed(payout_confirmed.clone()).to_string(),
                state: self.state.to_string(),
                reason: None
            }),
        }
    }
}
