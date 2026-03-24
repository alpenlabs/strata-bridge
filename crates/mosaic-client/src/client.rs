use algebra::retry::retry_with;
use mosaic_rpc_types::{
    DepositStatus, EvaluatorDepositConfig, EvaluatorWithdrawalConfig, GarblerDepositConfig,
    RpcTablesetStatus,
};
use strata_bridge_primitives::subscription::Subscription;
use strata_mosaic_client_api::{
    IMosaicClient, MosaicError, MosaicEvent, MosaicSetupError, types::*,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use crate::{DepositId, MosaicApi, MosaicClient, MosaicIdResolver, util::make_setup_config};

#[async_trait::async_trait]
impl<R: MosaicApi, P: MosaicIdResolver> IMosaicClient for MosaicClient<R, P> {
    async fn ensure_mosaic_setup(
        &self,
        operator_idx: OperatorIdx,
        role: Role,
    ) -> Result<(), MosaicSetupError> {
        let peer_id = self
            .provider
            .resolve_peer_id(operator_idx)
            .await
            .map_err(MosaicSetupError::rpc_error)?;
        let operator_pubkey = self
            .provider
            .resolve_operator_pubkey(operator_idx)
            .await
            .map_err(MosaicSetupError::rpc_error)?;
        let setup_inputs: SetupInputs = operator_pubkey;

        // Initialize tableset setup for a given peer_id and role.
        // This call is a no-op in mosaic if the setup already exists.
        let rpc = self.rpc.clone();
        let tableset_id = retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            async move {
                rpc.setup_tableset(make_setup_config(peer_id, role, setup_inputs))
                    .await
                    .map_err(MosaicSetupError::rpc_error)
            }
        })
        .await?;

        // Wait until setup is complete
        loop {
            let rpc = self.rpc.clone();
            let status = retry_with(self.default_retry_strategy(), move || {
                let rpc = rpc.clone();
                async move {
                    rpc.get_tableset_status(tableset_id)
                        .await
                        .map_err(MosaicSetupError::rpc_error)
                }
            })
            .await?;

            match status {
                RpcTablesetStatus::Incomplete { details } => {
                    // setup is incomplete, keep retrying
                    debug!(%details, "setup incomplete, retrying");
                    tokio::time::sleep(self.retry_delay).await;
                    continue;
                }
                RpcTablesetStatus::Aborted { reason } => {
                    // Mosaic setup has aborted due to a protocol violation.
                    // This setup cannot be used again, needs manual intervention to resolve and
                    // retry.
                    error!(%reason, "setup aborted");
                    return Err(MosaicSetupError::Aborted(reason));
                }
                RpcTablesetStatus::SetupComplete
                | RpcTablesetStatus::Contest { .. }
                | RpcTablesetStatus::Consumed { .. } => {
                    info!("setup complete");

                    self.tablesets
                        .write()
                        .await
                        .insert((role, operator_idx), tableset_id);

                    return Ok(());
                }
            }
        }
    }

    async fn get_fault_pubkey(
        &self,
        operator_idx: OperatorIdx,
        role: Role,
    ) -> Result<Option<PubKey>, MosaicError> {
        let tableset_id = self.get_tableset_id(role, operator_idx).await?;
        let rpc = self.rpc.clone();
        let pubkey = retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            async move {
                rpc.get_fault_secret_pubkey(tableset_id)
                    .await
                    .map_err(MosaicError::rpc_error)
            }
        })
        .await?;

        Ok(pubkey)
    }

    async fn get_adaptor_pubkey(
        &self,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
    ) -> Result<Option<PubKey>, MosaicError> {
        let tableset_id = self.get_tableset_id(Role::Evaluator, operator_idx).await?;
        let deposit_id = self.provider.resolve_deposit_id(deposit_idx).await?;
        let rpc_deposit_id = deposit_id.into();
        let rpc = self.rpc.clone();
        let pubkey = retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            async move {
                rpc.evaluator_get_adaptor_pubkey(tableset_id, rpc_deposit_id)
                    .await
                    .map_err(MosaicError::rpc_error)
            }
        })
        .await?;

        Ok(pubkey)
    }

    async fn init_evaluator_deposit(
        &self,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
        sighashes: DepositSighashes,
    ) -> Result<PubKey, MosaicError> {
        let tableset_id = self.get_tableset_id(Role::Evaluator, operator_idx).await?;
        let deposit_id = self.provider.resolve_deposit_id(deposit_idx).await?;
        let deposit_inputs: DepositInputs = deposit_idx.to_le_bytes();

        // Initialize evaluator deposit on mosaic with provided configs.
        let rpc = self.rpc.clone();
        let deposit_config = EvaluatorDepositConfig {
            deposit_inputs: deposit_inputs.into(),
            sighashes: sighashes.into(),
        };
        let rpc_deposit_id = deposit_id.into();
        retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            let deposit_config = deposit_config.clone();
            async move {
                rpc.init_evaluator_deposit(tableset_id, rpc_deposit_id, deposit_config)
                    .await
                    .map_err(MosaicError::rpc_error)
            }
        })
        .await?;

        // Wait for any status to be received to ensure that the deposit was accepted by mosaic.
        // If this fails to get any status after exhausting all retries, the deposit init failed or
        // there was a connectivity issue.
        let rpc = self.rpc.clone();
        let _ = retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            async move {
                rpc.get_deposit_status(tableset_id, rpc_deposit_id)
                    .await
                    .map_err(MosaicError::rpc_error)
            }
        })
        .await?;

        // Retrieve the adaptor pubkey for this deposit.
        let rpc = self.rpc.clone();
        let pubkey = retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            async move {
                rpc.evaluator_get_adaptor_pubkey(tableset_id, rpc_deposit_id)
                    .await
                    .map_err(MosaicError::rpc_error)
            }
        })
        .await?
        .ok_or(MosaicError::UnexpectedMissingFinalSecret(deposit_idx))?;

        Ok(pubkey)
    }

    async fn init_garbler_deposit(
        &self,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
        sighashes: DepositSighashes,
        adaptor_pubkey: PubKey,
    ) -> Result<(), MosaicError> {
        let tableset_id = self.get_tableset_id(Role::Garbler, operator_idx).await?;
        let deposit_id = self.provider.resolve_deposit_id(deposit_idx).await?;
        let deposit_inputs: DepositInputs = deposit_idx.to_le_bytes();

        // Initialize garbler deposit process on mosaic with provided configs.
        let rpc = self.rpc.clone();
        let deposit_config = GarblerDepositConfig {
            deposit_inputs: deposit_inputs.into(),
            sighashes: sighashes.into(),
            adaptor_pk: adaptor_pubkey,
        };
        let rpc_deposit_id = deposit_id.into();
        retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            let deposit_config = deposit_config.clone();
            async move {
                rpc.init_garbler_deposit(tableset_id, rpc_deposit_id, deposit_config)
                    .await
                    .map_err(MosaicError::rpc_error)
            }
        })
        .await?;

        // Wait for some status to be received
        // If this fails to get any status after exhausting all retries, it indicates that the
        // deposit init failed.
        let rpc = self.rpc.clone();
        let status = retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            async move {
                rpc.get_deposit_status(tableset_id, rpc_deposit_id)
                    .await
                    .map_err(MosaicError::rpc_error)
            }
        })
        .await?;

        match status {
            DepositStatus::Aborted { reason } => {
                error!(%reason, %deposit_idx, "deposit aborted on mosaic");
                return Err(MosaicError::DepositAborted(deposit_idx));
            }
            DepositStatus::UncontestedWithdrawal | DepositStatus::Consumed { .. } => {
                error!(%deposit_idx, "deposit is already withdrawn");
                return Err(MosaicError::DepositWithdrawn(deposit_idx));
            }
            DepositStatus::Incomplete { details } => {
                // deposit is incomplete
                // add to watched deposits to emit verified event when ready.
                debug!(%details, %deposit_idx, "deposit process pending");
                self.watched_deposits
                    .lock()
                    .await
                    .insert((tableset_id, operator_idx, deposit_idx), 0);
            }
            DepositStatus::Ready => {
                // deposit is already ready, emit verified event directly.
                info!(%deposit_idx, "deposit adaptors verified");
                self.emit(MosaicEvent::AdaptorsVerified {
                    operator_idx,
                    deposit_idx,
                })
                .await;
            }
        }

        Ok(())
    }

    // ---- Withdrawal ----

    async fn mark_deposit_withdrawn(
        &self,
        operator_idx: OperatorIdx,
        role: Role,
        deposit_idx: DepositIdx,
    ) -> Result<(), MosaicError> {
        let tableset_id = self.get_tableset_id(role, operator_idx).await?;
        let deposit_id = self.provider.resolve_deposit_id(deposit_idx).await?;

        let rpc = self.rpc.clone();
        let rpc_deposit_id = deposit_id.into();
        retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            async move {
                rpc.mark_deposit_withdrawn(tableset_id, rpc_deposit_id)
                    .await
                    .map_err(MosaicError::rpc_error)
            }
        })
        .await?;

        Ok(())
    }

    async fn complete_adaptor_sigs(
        &self,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
        counterproof: G16ProofRaw,
    ) -> Result<CompletedSignatures, MosaicError> {
        let tableset_id = self.get_tableset_id(Role::Garbler, operator_idx).await?;
        let deposit_id = self.provider.resolve_deposit_id(deposit_idx).await?;
        let rpc_deposit_id = deposit_id.into();
        let withdrawal_inputs: WithdrawalInputs = counterproof.0;

        let rpc = self.rpc.clone();
        let rpc_withdrawal_inputs = withdrawal_inputs.into();
        retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            async move {
                rpc.complete_adaptor_sigs(tableset_id, rpc_deposit_id, rpc_withdrawal_inputs)
                    .await
                    .map_err(MosaicError::rpc_error)
            }
        })
        .await?;

        loop {
            let rpc = self.rpc.clone();
            let status = retry_with(self.default_retry_strategy(), move || {
                let rpc = rpc.clone();

                async move {
                    rpc.get_tableset_status(tableset_id)
                        .await
                        .map_err(MosaicError::rpc_error)
                }
            })
            .await?;
            match status {
                RpcTablesetStatus::Incomplete { details } => {
                    error!(%details, "unexpected deposit state");
                    debug_assert!(
                        false,
                        "mosaic garbler deposit cannot be in incomplete state at this point"
                    );
                    return Err(MosaicError::UnexpectedDepositState(details));
                }
                RpcTablesetStatus::SetupComplete => {
                    // complete_adaptor_sigs has not yet been processed, wait
                    debug!(%deposit_idx, "waiting for transition from SetupComplete");
                    continue;
                }
                RpcTablesetStatus::Contest { deposit } => {
                    // setup is being contested
                    let actual_deposit_id: DepositId = deposit.into();
                    if deposit_id != actual_deposit_id {
                        // deposit being contested is NOT this deposit
                        error!(expected = %hex::encode(deposit_id), actual = %hex::encode(actual_deposit_id), "unexpected deposit_id being contested");
                        return Err(MosaicError::UnexpectedDepositContest {
                            expected: hex::encode(deposit_id),
                            actual: hex::encode(actual_deposit_id),
                        });
                    }
                    // adaptor sig completion not complete yet, wait
                    debug!(%deposit_idx, "waiting for transition from Contest");
                    continue;
                }
                RpcTablesetStatus::Consumed {
                    deposit,
                    success: _,
                } => {
                    // setup is consumed
                    let actual_deposit_id: DepositId = deposit.into();
                    if deposit_id != actual_deposit_id {
                        // consumed deposit is NOT this deposit
                        error!(expected = %hex::encode(deposit_id), actual = %hex::encode(actual_deposit_id), "unexpected deposit_id consumed");
                        return Err(MosaicError::UnexpectedDepositContest {
                            expected: hex::encode(deposit_id),
                            actual: hex::encode(actual_deposit_id),
                        });
                    }
                    info!(
                        %deposit_idx,
                        "setup consumed; signed adaptors should be ready"
                    );
                    break;
                }
                RpcTablesetStatus::Aborted { reason } => {
                    // this setup has already been aborted
                    error!(%reason, "setup aborted");
                    return Err(MosaicError::Aborted(reason));
                }
            }
        }

        let rpc = self.rpc.clone();
        let completed_sigs = retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            async move {
                rpc.get_completed_adaptor_sigs(tableset_id)
                    .await
                    .map_err(MosaicError::rpc_error)
            }
        })
        .await?
        .into();

        Ok(completed_sigs)
    }

    async fn evaluate_and_sign(
        &self,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
        counterproof: G16ProofRaw,
        completed_signatures: CompletedSignatures,
        sighash: [u8; 32],
        tweak: Option<[u8; 32]>,
    ) -> Result<Option<Signature>, MosaicError> {
        let tableset_id = self.get_tableset_id(Role::Evaluator, operator_idx).await?;
        let deposit_id = self.provider.resolve_deposit_id(deposit_idx).await?;
        let rpc_deposit_id = deposit_id.into();
        let withdrawal_inputs: WithdrawalInputs = counterproof.0;

        let rpc = self.rpc.clone();
        let withdrawal_config = EvaluatorWithdrawalConfig {
            withdrawal_inputs: withdrawal_inputs.into(),
            completed_signatures: completed_signatures.into(),
        };

        retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            let withdrawal_config = withdrawal_config.clone();
            async move {
                rpc.evaluate_tableset(tableset_id, rpc_deposit_id, withdrawal_config)
                    .await
                    .map_err(MosaicError::rpc_error)
            }
        })
        .await?;

        loop {
            let rpc = self.rpc.clone();
            let status = retry_with(self.default_retry_strategy(), move || {
                let rpc = rpc.clone();
                async move {
                    rpc.get_tableset_status(tableset_id)
                        .await
                        .map_err(MosaicError::rpc_error)
                }
            })
            .await?;
            match status {
                RpcTablesetStatus::Incomplete { details } => {
                    error!(%details, "unexpected deposit state");
                    debug_assert!(
                        false,
                        "mosaic evaluator deposit sm cannot be in incomplete state at this point"
                    );
                    return Err(MosaicError::UnexpectedDepositState(details));
                }
                RpcTablesetStatus::SetupComplete => {
                    // `complete_adaptor_sigs` has not yet been processed, wait.
                    debug!(%deposit_idx, "waiting for transition from SetupComplete");
                    continue;
                }
                RpcTablesetStatus::Contest { deposit } => {
                    // Setup is being contested.
                    let actual_deposit_id: DepositId = deposit.into();
                    if deposit_id != actual_deposit_id {
                        // Deposit being contested is NOT this deposit.
                        error!(expected = %hex::encode(deposit_id), actual = %hex::encode(actual_deposit_id), "unexpected deposit_id being contested");
                        return Err(MosaicError::UnexpectedDepositContest {
                            expected: hex::encode(deposit_id),
                            actual: hex::encode(actual_deposit_id),
                        });
                    }
                    // Adaptor sig completion not complete yet, wait.
                    debug!(%deposit_idx, "waiting for transition from Contest");
                    continue;
                }
                RpcTablesetStatus::Consumed { deposit, success } => {
                    // Setup is already consumed.
                    let actual_deposit_id: DepositId = deposit.into();
                    if deposit_id != actual_deposit_id {
                        // Consumed deposit is NOT this deposit.
                        error!(expected = %hex::encode(deposit_id), actual = %hex::encode(actual_deposit_id), "unexpected deposit_id consumed");
                        return Err(MosaicError::UnexpectedDepositContest {
                            expected: hex::encode(deposit_id),
                            actual: hex::encode(actual_deposit_id),
                        });
                    }

                    // Garbling table evaluation failed to extract fault secret.
                    if !success {
                        error!(%operator_idx, %deposit_idx, "evaluation failed to extract fault secret");
                        return Ok(None);
                    }
                    info!(
                        %deposit_idx,
                        "setup consumed; signed adaptors should be ready"
                    );
                    break;
                }
                RpcTablesetStatus::Aborted { reason } => {
                    // this setup has already been aborted
                    error!(%reason, "setup aborted");
                    return Err(MosaicError::Aborted(reason));
                }
            }
        }

        let rpc = self.rpc.clone();

        // evaluation successful
        let signature = retry_with(self.default_retry_strategy(), move || {
            let rpc = rpc.clone();
            async move {
                rpc.sign_with_fault_secret(tableset_id, sighash.into(), tweak.map(Into::into))
                    .await
                    .map_err(MosaicError::rpc_error)?
                    .ok_or_else(|| MosaicError::UnexpectedMissingFinalSecret(deposit_idx))
            }
        })
        .await?;

        Ok(Some(signature))
    }

    fn subscribe_events(&self) -> Subscription<MosaicEvent> {
        let (send, recv) = mpsc::unbounded_channel();

        // We need to block_in_place or use try_lock since this is now sync.
        // Since subscribers is behind a Mutex, we use blocking_lock.
        self.subscribers.blocking_lock().push(send);

        Subscription::from_receiver(recv)
    }
}
