use std::collections::BTreeMap;

use bitcoin::Transaction;
use musig2::{
    AggNonce, PartialSignature, PubNonce, aggregate_partial_signatures, secp256k1::schnorr,
    verify_partial,
};
use strata_bridge_primitives::{
    key_agg::create_agg_ctx, scripts::prelude::TaprootWitness, types::OperatorIdx,
};
use strata_bridge_tx_graph2::transactions::PresignedTx;

use crate::{
    deposit::{
        duties::DepositDuty,
        errors::{DSMError, DSMResult},
        events::DepositEvent,
        machine::{DSMOutput, DepositSM},
        state::DepositState,
    },
    signals::{DepositSignal, GraphToDeposit},
    state_machine::SMOutput,
};

impl DepositSM {
    /// Processes the event where the user takes back the deposit request output.
    ///
    /// This can happen if any of the operators are not operational for the entire duration of the
    /// take back period.
    // TODO: Add event description as a parameter so that event needn't be recreated to
    //       for the error.
    pub(crate) fn process_drt_takeback(
        &mut self,
        tx: Transaction,
    ) -> Result<SMOutput<DepositDuty, DepositSignal>, DSMError> {
        let deposit_request_outpoint = &self.cfg().deposit_outpoint;
        match self.state() {
            DepositState::Created { .. }
            | DepositState::GraphGenerated { .. }
            | DepositState::DepositNoncesCollected { .. }
            | DepositState::DepositPartialsCollected { .. } => {
                // FIXME: (@Rajil1213) Check if `txid` is not that of a Deposit Transaction instead
                if tx
                    .input
                    .iter()
                    .find(|input| input.previous_output == *deposit_request_outpoint)
                    .is_some_and(|input| input.witness.len() > 1)
                // HACK: (@Rajil1213) `N/N` spend is a keypath spend that only has a single witness
                // element (the `N/N` signature). If it has more than one element, it implies that
                // it is not a keypath spend (since there can only be 1 keypath spend for a taproot
                // output). This implies that if there are more than 1 witness elements, it is not a
                // Deposit Transaction and so must be a takeback (the script-spend path in the DRT
                // output).
                {
                    // Transition to Aborted state
                    self.state = DepositState::Aborted;

                    // This is a terminal state
                    Ok(SMOutput {
                        duties: vec![],
                        signals: vec![],
                    })
                } else {
                    Err(DSMError::Rejected {
                        state: Box::new(self.state().clone()),
                        reason: format!(
                            "Transaction {} is not a take back transaction for the deposit request outpoint {}",
                            tx.compute_txid(),
                            deposit_request_outpoint
                        ),
                        event: Box::new(DepositEvent::UserTakeBack { tx }),
                    })
                }
            }
            DepositState::Aborted => Err(DSMError::Duplicate {
                state: Box::new(self.state().clone()),
                event: Box::new(DepositEvent::UserTakeBack { tx }),
            }),
            _ => Err(DSMError::InvalidEvent {
                event: DepositEvent::UserTakeBack { tx }.to_string(),
                state: self.state.to_string(),
                reason: None,
            }),
        }
    }

    /// Processes the event where an operator's graph becomes available.
    ///
    /// This tracks operators that have successfully generated and linked their spending graphs
    /// for this deposit. When all operators have linked their graphs, transitions to the
    /// [`DepositState::GraphGenerated`] state.
    pub(crate) fn process_graph_available(
        &mut self,
        graph_msg: GraphToDeposit,
    ) -> DSMResult<DSMOutput> {
        let operator_table_cardinality = self.cfg().operator_table.cardinality();
        let deposit_outpoint = self.cfg().deposit_outpoint();

        match graph_msg {
            GraphToDeposit::GraphAvailable { operator_idx } => {
                // Validate operator_idx is in the operator table
                if !self.validate_operator_idx(operator_idx) {
                    return Err(DSMError::Rejected {
                        state: Box::new(self.state().clone()),
                        reason: format!("Operator index {} not in operator table", operator_idx),
                        event: Box::new(DepositEvent::GraphMessage(graph_msg)),
                    });
                }

                match self.state_mut() {
                    DepositState::Created {
                        deposit_transaction,
                        last_block_height,
                        linked_graphs,
                    } => {
                        // Check for duplicate graph submission
                        if linked_graphs.contains(&operator_idx) {
                            return Err(DSMError::Duplicate {
                                state: Box::new(self.state().clone()),
                                event: Box::new(DepositEvent::GraphMessage(
                                    GraphToDeposit::GraphAvailable { operator_idx },
                                )),
                            });
                        }

                        linked_graphs.insert(operator_idx);

                        if linked_graphs.len() == operator_table_cardinality {
                            // All operators have linked their graphs, transition to GraphGenerated
                            // state
                            let new_state = DepositState::GraphGenerated {
                                deposit_transaction: deposit_transaction.clone(),
                                last_block_height: *last_block_height,
                                pubnonces: BTreeMap::new(),
                            };
                            self.state = new_state;

                            // Create the duty to publish deposit nonce
                            let duty = DepositDuty::PublishDepositNonce { deposit_outpoint };

                            return Ok(DSMOutput::with_duties(vec![duty]));
                        }

                        Ok(DSMOutput::new())
                    }
                    _ => Err(DSMError::InvalidEvent {
                        state: self.state().to_string(),
                        event: DepositEvent::GraphMessage(graph_msg).to_string(),
                        reason: None,
                    }),
                }
            }
        }
    }

    /// Processes the event where an operator's nonce is received for the deposit transaction.
    ///
    /// This collects public nonces from operators required for the multisig signing process.
    /// When all operators have provided their nonces, transitions to the
    /// [`DepositState::DepositNoncesCollected`] state and emits a
    /// [`DepositDuty::PublishDepositPartial`] duty.
    pub(crate) fn process_nonce_received(
        &mut self,
        nonce: PubNonce,
        operator_idx: OperatorIdx,
    ) -> DSMResult<DSMOutput> {
        let operator_table_cardinality = self.cfg().operator_table.cardinality();

        // Validate operator_idx is in the operator table
        if !self.validate_operator_idx(operator_idx) {
            return Err(DSMError::Rejected {
                state: Box::new(self.state().clone()),
                reason: format!("Operator index {} not in operator table", operator_idx),
                event: Box::new(DepositEvent::NonceReceived {
                    nonce,
                    operator_idx,
                }),
            });
        }

        match self.state_mut() {
            DepositState::GraphGenerated {
                deposit_transaction,
                last_block_height,
                pubnonces,
            } => {
                // Check for duplicate nonce submission
                if pubnonces.contains_key(&operator_idx) {
                    return Err(DSMError::Duplicate {
                        state: Box::new(self.state().clone()),
                        event: Box::new(DepositEvent::NonceReceived {
                            nonce,
                            operator_idx,
                        }),
                    });
                }

                // Insert the new nonce into the map
                pubnonces.insert(operator_idx, nonce);

                // Check if we have collected all nonces
                if pubnonces.len() == operator_table_cardinality {
                    // All nonces collected, compute the aggregated nonce
                    let agg_nonce = AggNonce::sum(pubnonces.values().cloned());

                    // Derive the sighash message for the deposit transaction
                    let deposit_sighash = deposit_transaction
                        .signing_info()
                        .first()
                        .expect("deposit transaction must have signing info")
                        .sighash;

                    // Transition to DepositNoncesCollected state
                    let new_state = DepositState::DepositNoncesCollected {
                        deposit_transaction: deposit_transaction.clone(),
                        last_block_height: *last_block_height,
                        agg_nonce: agg_nonce.clone(),
                        pubnonces: pubnonces.clone(),
                        partial_signatures: BTreeMap::new(),
                    };
                    self.state = new_state;

                    // Create the duty to publish deposit partials
                    let duty = DepositDuty::PublishDepositPartial {
                        deposit_outpoint: self.cfg().deposit_outpoint(),
                        deposit_sighash,
                        deposit_agg_nonce: agg_nonce,
                    };

                    Ok(DSMOutput::with_duties(vec![duty]))
                } else {
                    // Not all nonces collected yet, stay in current state
                    Ok(DSMOutput::new())
                }
            }
            _ => Err(DSMError::InvalidEvent {
                state: self.state().to_string(),
                event: DepositEvent::NonceReceived {
                    nonce,
                    operator_idx,
                }
                .to_string(),
                reason: None,
            }),
        }
    }

    /// Processes the event where an operator's partial signature is received for the deposit
    /// transaction.
    ///
    /// This collects partial signatures from operators required for the multisig signing process.
    /// When all operators have provided their partial signatures, transitions to the
    /// [`DepositState::DepositPartialsCollected`] state and emits a [`DepositDuty::PublishDeposit`]
    /// duty.
    pub(crate) fn process_partial_received(
        &mut self,
        partial_sig: PartialSignature,
        operator_idx: OperatorIdx,
    ) -> DSMResult<DSMOutput> {
        let operator_table_cardinality = self.cfg().operator_table.cardinality();
        let btc_keys: Vec<_> = self.cfg().operator_table.btc_keys().into_iter().collect();

        // Validate operator_idx is in the operator table
        if !self.validate_operator_idx(operator_idx) {
            return Err(DSMError::Rejected {
                state: Box::new(self.state().clone()),
                reason: format!("Operator index {} not in operator table", operator_idx),
                event: Box::new(DepositEvent::PartialReceived {
                    partial_sig,
                    operator_idx,
                }),
            });
        }

        // Get the operator pubkey (safe after validation)
        let operator_pubkey = self
            .cfg()
            .operator_table
            .idx_to_btc_key(&operator_idx)
            .expect("validated above");

        match self.state_mut() {
            DepositState::DepositNoncesCollected {
                deposit_transaction,
                last_block_height,
                agg_nonce,
                pubnonces,
                partial_signatures,
            } => {
                // Extract Copy types immediately using dereference pattern to bypass borrow checker
                let blk_height = *last_block_height;

                // Check for duplicate partial signature submission
                if partial_signatures.contains_key(&operator_idx) {
                    return Err(DSMError::Duplicate {
                        state: Box::new(self.state().clone()),
                        event: Box::new(DepositEvent::PartialReceived {
                            partial_sig,
                            operator_idx,
                        }),
                    });
                }

                // Extract signing info once - used for both verification and aggregation
                let signing_info = deposit_transaction
                    .signing_info()
                    .first()
                    .copied()
                    .expect("deposit transaction must have signing info");
                let sighash = signing_info.sighash;
                let tweak = signing_info
                    .tweak
                    .expect("DRT->DT key-path spend must include a taproot tweak")
                    .expect("tweak must be present for deposit transaction");

                let tap_witness = TaprootWitness::Tweaked { tweak };

                // Create key aggregation context once - reused for verification and aggregation
                let key_agg_ctx = create_agg_ctx(btc_keys, &tap_witness)
                    .expect("must be able to create key aggregation context");

                // Verify the partial signature
                let operator_pubnonce = pubnonces
                    .get(&operator_idx)
                    .expect("operator must have submitted nonce")
                    .clone();
                if verify_partial(
                    &key_agg_ctx,
                    partial_sig,
                    agg_nonce,
                    operator_pubkey,
                    &operator_pubnonce,
                    sighash.as_ref(),
                )
                .is_err()
                {
                    return Err(DSMError::Rejected {
                        state: Box::new(self.state().clone()),
                        reason: "Invalid partial signature".to_string(),
                        event: Box::new(DepositEvent::PartialReceived {
                            partial_sig,
                            operator_idx,
                        }),
                    });
                }

                // Insert the new partial signature into the map
                partial_signatures.insert(operator_idx, partial_sig);

                // Check if we have collected all partial signatures
                if partial_signatures.len() == operator_table_cardinality {
                    // Clone deposit transaction for state transition
                    let deposit_tx = deposit_transaction.clone();

                    // Aggregate all partial signatures using the same key_agg_ctx
                    let agg_signature: schnorr::Signature = aggregate_partial_signatures(
                        &key_agg_ctx,
                        agg_nonce,
                        partial_signatures.values().cloned(),
                        sighash.as_ref(),
                    )
                    .expect("partial signatures must be valid");

                    // Build deposit transaction with sigs
                    let deposit_transaction = deposit_tx.finalize(agg_signature);

                    // Transition to DepositPartialsCollected state
                    self.state = DepositState::DepositPartialsCollected {
                        deposit_transaction: deposit_transaction.clone(),
                        last_block_height: blk_height,
                    };

                    // Create the duty to publish the deposit transaction
                    let duty = DepositDuty::PublishDeposit {
                        deposit_transaction,
                        agg_signature,
                    };

                    Ok(DSMOutput::with_duties(vec![duty]))
                } else {
                    Ok(DSMOutput::new())
                }
            }
            _ => Err(DSMError::InvalidEvent {
                state: self.state().to_string(),
                event: DepositEvent::PartialReceived {
                    partial_sig,
                    operator_idx,
                }
                .to_string(),
                reason: None,
            }),
        }
    }

    /// Processes the event where the deposit transaction is confirmed on-chain.
    ///
    /// Verifies that the confirmed transaction matches the expected deposit
    /// transaction and transitions the state machine to [`DepositState::Deposited`].
    ///
    /// This event may be accepted from either [`DepositState::DepositPartialsCollected`]
    /// or [`DepositState::DepositNoncesCollected`] (in case an operator broadcasts
    /// the transaction early).
    pub(crate) fn process_deposit_confirmed(
        &mut self,
        event_description: String,
        confirmed_deposit_transaction: Transaction,
    ) -> DSMResult<DSMOutput> {
        match self.state() {
            DepositState::DepositPartialsCollected {
                last_block_height,
                deposit_transaction,
                ..
            } => {
                // Ensure that the deposit transaction confirmed on-chain is the one we were
                // expecting.
                if confirmed_deposit_transaction.compute_txid()
                    != deposit_transaction.compute_txid()
                {
                    return Err(DSMError::Rejected {
                        state: Box::new(self.state().clone()),
                        event: Box::new(DepositEvent::DepositConfirmed {
                            deposit_transaction: deposit_transaction.clone(),
                        }),
                        reason:
                            "Transaction confirmed on chain does not match expected deposit transaction"
                                .to_string(),
                    });
                }
                // Transition to the Deposited State
                self.state = DepositState::Deposited {
                    last_block_height: *last_block_height,
                };
                // No duties or signals required
                Ok(DSMOutput::new())
            }

            // This can happen if one of the operators withholds their own partial signature
            // while aggregating it with the rest of the collected partials and broadcasts it
            // unilaterally.
            DepositState::DepositNoncesCollected {
                last_block_height,
                deposit_transaction,
                ..
            } => {
                // Ensure that the deposit transaction confirmed on-chain is the one we were
                // expecting.
                if confirmed_deposit_transaction.compute_txid()
                    != deposit_transaction.as_ref().compute_txid()
                {
                    return Err(DSMError::Rejected {
                        state: Box::new(self.state().clone()),
                        event: Box::new(DepositEvent::DepositConfirmed {
                            deposit_transaction: confirmed_deposit_transaction,
                        }),
                        reason:
                            "Transaction confirmed on chain does not match expected deposit transaction"
                                .to_string(),
                    });
                }
                // Transition to the Deposited State
                self.state = DepositState::Deposited {
                    last_block_height: *last_block_height,
                };
                // No duties or signals required
                Ok(DSMOutput::new())
            }

            _ => Err(DSMError::InvalidEvent {
                state: self.state.to_string(),
                event: event_description,
                reason: None,
            }),
        }
    }
}
