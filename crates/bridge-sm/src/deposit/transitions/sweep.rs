//! Transitions for the safe-harbour sweep of the deposit UTXO.
//!
//! The sweep mirrors the cooperative payout signing round with two differences: the payout
//! destination is the frozen safe-harbour descriptor injected via the seed event, and the
//! round is symmetric — there is no assignee, so every operator publishes its partial and
//! every operator finalizes and broadcasts the identical deterministic transaction.

use std::{collections::BTreeMap, sync::Arc};

use musig2::{AggNonce, verify_partial};
use strata_bridge_connectors::n_of_n::NOfNConnector;
use strata_bridge_primitives::{key_agg::create_agg_ctx, scripts::taproot::TaprootTweak};
use strata_bridge_tx_graph::transactions::prelude::{SweepData, SweepTx};

use crate::deposit::{
    config::DepositSMCfg,
    duties::DepositDuty,
    errors::{DSMError, DSMResult},
    events::{SweepNonceReceivedEvent, SweepPartialReceivedEvent, SweepRequestedEvent},
    machine::{DSMOutput, DepositSM},
    state::DepositState,
};

impl DepositSM {
    /// Processes the event requesting that this deposit be swept to the safe-harbour descriptor.
    ///
    /// Valid from every state holding a live deposit UTXO: the deposit outpoint is a fixed
    /// N-of-N key-path output that withdrawal progress never touches, so the sweep transaction
    /// is built identically from any source state and whatever withdrawal-progress the source
    /// carried (assignee, fulfillment txid, in-flight payout session) is discarded.
    ///
    /// Builds the sweep transaction and transitions to [`DepositState::SweepNoncesPending`],
    /// emitting a [`DepositDuty::PublishSweepNonce`] duty for every operator.
    pub(crate) fn process_sweep_request(
        &mut self,
        cfg: Arc<DepositSMCfg>,
        sweep_request: SweepRequestedEvent,
    ) -> DSMResult<DSMOutput> {
        // Extract values before the match to avoid borrow conflicts
        let n_of_n_pubkey = self.context.operator_table().aggregated_btc_key().into();
        let deposit_outpoint = self.context.deposit_outpoint();
        let deposit_idx = self.context.deposit_idx();
        let ordered_pubkeys: Vec<_> = self
            .context
            .operator_table()
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();

        let last_block_height = match self.state() {
            DepositState::Deposited { last_block_height }
            | DepositState::Assigned {
                last_block_height, ..
            }
            | DepositState::Fulfilled {
                last_block_height, ..
            }
            | DepositState::PayoutDescriptorReceived {
                last_block_height, ..
            }
            | DepositState::PayoutNoncesCollected {
                last_block_height, ..
            }
            | DepositState::CooperativePathFailed {
                last_block_height, ..
            } => *last_block_height,

            // The per-block scan re-emits SweepRequested until the deposit leaves the live-UTXO
            // states, so a sweep already in progress (or completed) is a duplicate, not an error.
            DepositState::SweepNoncesPending { .. }
            | DepositState::SweepNoncesCollected { .. }
            | DepositState::Spent { .. } => {
                return Err(DSMError::duplicate(
                    self.state().clone(),
                    sweep_request.into(),
                ));
            }

            DepositState::Created { .. }
            | DepositState::GraphGenerated { .. }
            | DepositState::DepositNoncesCollected { .. }
            | DepositState::DepositPartialsCollected { .. }
            | DepositState::Aborted => {
                return Err(DSMError::invalid_event(
                    self.state().clone(),
                    sweep_request.into(),
                    None,
                ));
            }
        };

        // Build the sweep transaction to the frozen safe-harbour descriptor
        let deposit_connector =
            NOfNConnector::new(cfg.network(), n_of_n_pubkey, cfg.deposit_amount());
        let sweep_tx = SweepTx::new(
            SweepData { deposit_outpoint },
            deposit_connector,
            sweep_request.safe_harbour_desc,
            ordered_pubkeys.clone(),
            cfg.sweep_fee_rate(),
        );

        let sweep_sighash = sweep_tx
            .signing_info()
            .first()
            .expect("sweep transaction must have signing info")
            .sighash;

        // Transition to the SweepNoncesPending state
        self.state = DepositState::SweepNoncesPending {
            last_block_height,
            sweep_tx,
            sweep_nonces: BTreeMap::new(),
        };

        // Dispatch the duty to publish the sweep nonce
        Ok(DSMOutput::with_duties(vec![
            DepositDuty::PublishSweepNonce {
                deposit_idx,
                deposit_outpoint,
                ordered_pubkeys,
                // NOfNConnector uses key-path spend with no script tree
                tweak: TaprootTweak::Key { tweak: None },
                sweep_sighash,
            },
        ]))
    }

    /// Processes the event where an operator's sweep nonce is received.
    ///
    /// Collects sweep nonces required for the sweep signing round. Once all nonces are
    /// collected, transitions to [`DepositState::SweepNoncesCollected`] and emits a
    /// [`DepositDuty::PublishSweepPartial`] duty for every operator (no assignee asymmetry).
    pub(crate) fn process_sweep_nonce_received(
        &mut self,
        sweep_nonce: SweepNonceReceivedEvent,
    ) -> DSMResult<DSMOutput> {
        // Validate operator_idx is in the operator table
        self.check_operator_idx(sweep_nonce.operator_idx, &sweep_nonce)?;

        let operator_table_cardinality = self.context.operator_table().cardinality();

        match self.state_mut() {
            DepositState::SweepNoncesPending {
                last_block_height,
                sweep_tx,
                sweep_nonces,
            } => {
                // Check for duplicate nonce submission. If an entry from the same operator exists,
                // return with an error.
                if sweep_nonces.contains_key(&sweep_nonce.operator_idx) {
                    return Err(DSMError::duplicate(
                        self.state().clone(),
                        sweep_nonce.into(),
                    ));
                }
                // Update the sweep nonces with the new nonce just received.
                sweep_nonces.insert(sweep_nonce.operator_idx, sweep_nonce.sweep_nonce);

                // Transition to the SweepNoncesCollected state if *all* the nonces have been
                // received and dispatch the duty to publish the sweep partial signature.
                if operator_table_cardinality == sweep_nonces.len() {
                    // Compute the aggregated nonce from the collected nonces.
                    let agg_nonce = AggNonce::sum(sweep_nonces.values());

                    // Derive the sighash of the sweep transaction.
                    let sweep_sighash = sweep_tx
                        .signing_info()
                        .first()
                        .expect("sweep transaction must have signing info")
                        .sighash;

                    // Transition to the SweepNoncesCollected state.
                    self.state = DepositState::SweepNoncesCollected {
                        last_block_height: *last_block_height,
                        sweep_tx: sweep_tx.clone(),
                        sweep_agg_nonce: agg_nonce.clone(),
                        sweep_nonces: sweep_nonces.clone(),
                        sweep_partials: BTreeMap::new(),
                    };

                    // Unlike the cooperative payout, the sweep round is symmetric: *every*
                    // operator publishes its partial signature.
                    let ordered_pubkeys = self
                        .context
                        .operator_table()
                        .btc_keys()
                        .into_iter()
                        .map(|pk| pk.x_only_public_key().0)
                        .collect();

                    Ok(DSMOutput::with_duties(vec![
                        DepositDuty::PublishSweepPartial {
                            deposit_idx: self.context.deposit_idx(),
                            deposit_outpoint: self.context.deposit_outpoint(),
                            sweep_sighash,
                            agg_nonce,
                            ordered_pubkeys,
                        },
                    ]))
                }
                // If all nonces are not yet collected, stay in the SweepNoncesPending state
                // and dispatch no duties or signals.
                else {
                    Ok(DSMOutput::new())
                }
            }

            state => {
                if matches!(
                    state,
                    DepositState::Created { .. }
                        | DepositState::GraphGenerated { .. }
                        | DepositState::DepositNoncesCollected { .. }
                        | DepositState::DepositPartialsCollected { .. }
                ) {
                    Err(DSMError::rejected(
                        self.state().clone(),
                        sweep_nonce.into(),
                        "Inapplicable SweepNonce event in pre-deposit state; expected state(s): SweepNoncesPending",
                    ))
                } else {
                    Err(DSMError::invalid_event(
                        self.state().clone(),
                        sweep_nonce.into(),
                        None,
                    ))
                }
            }
        }
    }

    /// Processes the event where an operator's sweep partial signature is received.
    ///
    /// Verifies and collects sweep partial signatures. Once *all* partials are collected,
    /// emits a [`DepositDuty::PublishSweep`] duty for every operator: the aggregated signature
    /// and transaction are deterministic, so each operator broadcasts the identical sweep and
    /// duplicates are rejected as already-known by the network.
    pub(crate) fn process_sweep_partial_received(
        &mut self,
        sweep_partial: SweepPartialReceivedEvent,
    ) -> DSMResult<DSMOutput> {
        // Validate operator_idx is in the operator table
        self.check_operator_idx(sweep_partial.operator_idx, &sweep_partial)?;

        // Extract context values before the match to avoid borrow conflicts
        let operator_table_cardinality = self.context.operator_table().cardinality();
        let deposit_outpoint = self.context.deposit_outpoint();
        let ordered_pubkeys: Vec<_> = self
            .context
            .operator_table()
            .btc_keys()
            .into_iter()
            .map(|pk| pk.x_only_public_key().0)
            .collect();
        // NOfNConnector uses key-path spend with no script tree, so we use
        // TaprootTweak::Key which applies with_unspendable_taproot_tweak()
        let key_agg_ctx = create_agg_ctx(
            self.context.operator_table().btc_keys(),
            &TaprootTweak::Key { tweak: None },
        )
        .expect("must be able to create key aggregation context");
        let operator_pubkey = self
            .context
            .operator_table
            .idx_to_btc_key(&sweep_partial.operator_idx)
            .expect("operator must be in table");

        match self.state_mut() {
            DepositState::SweepNoncesCollected {
                sweep_tx,
                sweep_agg_nonce,
                sweep_nonces,
                sweep_partials,
                ..
            } => {
                // Check for duplicate partial signature submission. If an entry from the same
                // operator exists, return with an error.
                if sweep_partials.contains_key(&sweep_partial.operator_idx) {
                    return Err(DSMError::duplicate(
                        self.state().clone(),
                        sweep_partial.into(),
                    ));
                }

                // Get the sighash from the stored sweep transaction
                let message = sweep_tx
                    .signing_info()
                    .first()
                    .expect("sweep transaction must have signing info")
                    .sighash;

                // Get the operator's pubnonce for verification.
                let operator_pubnonce = sweep_nonces
                    .get(&sweep_partial.operator_idx)
                    .expect("operator must have submitted nonce");

                // Verify the partial signature.
                if verify_partial(
                    &key_agg_ctx,
                    sweep_partial.partial_signature,
                    sweep_agg_nonce,
                    operator_pubkey,
                    operator_pubnonce,
                    message.as_ref(),
                )
                .is_err()
                {
                    return Err(DSMError::rejected(
                        self.state().clone(),
                        sweep_partial.into(),
                        "Partial Signature Verification Failed",
                    ));
                }

                // If the partial signature verification passes, add it to state
                sweep_partials.insert(sweep_partial.operator_idx, sweep_partial.partial_signature);

                // Unlike the cooperative payout (which waits for all partials except the
                // assignee's), the sweep waits for *all* partials so that every operator can
                // finalize and broadcast without a further signing step.
                if operator_table_cardinality == sweep_partials.len() {
                    Ok(DSMOutput::with_duties(vec![DepositDuty::PublishSweep {
                        deposit_outpoint,
                        agg_nonce: sweep_agg_nonce.clone(),
                        collected_partials: sweep_partials.clone(),
                        sweep_tx: Box::new(sweep_tx.clone()),
                        ordered_pubkeys,
                    }]))
                } else {
                    // If there are remaining partial signatures, stay in the same state.
                    Ok(DSMOutput::new())
                }
            }

            state => {
                if matches!(
                    state,
                    DepositState::Created { .. }
                        | DepositState::GraphGenerated { .. }
                        | DepositState::DepositNoncesCollected { .. }
                        | DepositState::DepositPartialsCollected { .. }
                ) {
                    Err(DSMError::rejected(
                        self.state().clone(),
                        sweep_partial.into(),
                        "Inapplicable SweepPartial event in pre-deposit state; expected state(s): SweepNoncesCollected",
                    ))
                } else {
                    Err(DSMError::invalid_event(
                        self.state().clone(),
                        sweep_partial.into(),
                        None,
                    ))
                }
            }
        }
    }
}
