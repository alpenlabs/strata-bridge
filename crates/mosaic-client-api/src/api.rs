use async_trait::async_trait;
use strata_bridge_primitives::subscription::Subscription;

use crate::{MosaicError, MosaicEvent, MosaicSetupError, types::*};

/// Mosaic client interface.
#[async_trait]
pub trait MosaicClientApi: Send + Sync + 'static {
    // ---- Setup ----

    /// Ensures that a mosaic tableset is set up for the given operator and role.
    ///
    /// If a tableset for this (operator, role) pair already exists and is complete,
    /// returns immediately. If it exists but is incomplete, waits for completion.
    /// If it does not exist, initiates setup and waits for completion.
    ///
    /// This is a long-running call that blocks until setup is done.
    /// If setup is aborted due to a protocol violation, returns an error.
    /// Bridge should not proceed ahead until all setups are completed successfully.
    async fn ensure_mosaic_setup(
        &self,
        operator_idx: OperatorIdx,
        role: Role,
    ) -> Result<(), MosaicSetupError>;

    // ---- Deposit ----

    /// Returns the pubkey of fault secret for a tableset of the given operator.
    /// Returns `None` if the tableset is not yet ready or missing
    /// (should not happen after `ensure_mosaic_setup`).
    async fn get_fault_pubkey(
        &self,
        operator_idx: OperatorIdx,
        role: Role,
    ) -> Result<Option<PubKey>, MosaicError>;

    /// Returns pubkey of adaptor secret for the evaluator tableset of the given operator.
    /// Returns `None` if the tableset is missing
    /// (should not happen after `ensure_mosaic_setup`).
    async fn get_adaptor_pubkey(
        &self,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
    ) -> Result<Option<PubKey>, MosaicError>;

    /// Initializes a deposit on an evaluator tableset and returns after deposit is accepted by
    /// mosaic.
    async fn init_evaluator_deposit(
        &self,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
        sighashes: DepositSighashes,
    ) -> Result<(), MosaicError>;

    /// Initializes a deposit on a garbler tableset and returns after deposit is
    /// accepted by mosaic.
    ///
    /// On mosaic side, it waits for adaptor signatures from the evaluator and
    /// verifies them.
    /// If verification succeeds, [`MosaicEvent`] subscribers will receive
    /// [`MosaicEvent::AdaptorsVerified`]. If verification fails or never completes, the deposit
    /// is stuck and the operator must manually verify and resolve the issue.
    async fn init_garbler_deposit(
        &self,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
        sighashes: DepositSighashes,
        adaptor_pubkey: PubKey,
    ) -> Result<(), MosaicError>;

    // ---- Withdrawal ----

    /// Marks a deposit as withdrawn without contest. Informational only.
    async fn mark_deposit_withdrawn(
        &self,
        operator_idx: OperatorIdx,
        role: Role,
        deposit_idx: DepositIdx,
    ) -> Result<(), MosaicError>;

    /// Garbler side: completes adaptor signatures for a contested withdrawal.
    ///
    /// This is a long-running call. The tableset is consumed after this.
    /// Idempotent: if already completed, returns the existing signatures
    /// and does not compute them again.
    async fn complete_adaptor_sigs(
        &self,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
        counterproof: G16ProofRaw,
    ) -> Result<CompletedSignatures, MosaicError>;

    /// Evaluator side: evaluates the tableset to extract the fault secret
    /// and signs the given digest.
    ///
    /// This is a long-running call. The tableset is consumed after this.
    /// Idempotent: if evaluation is already completed, signs with the
    /// already-extracted fault secret without re-evaluating.
    /// Returns `None` if the fault secret could not be extracted.
    async fn evaluate_and_sign(
        &self,
        operator_idx: OperatorIdx,
        deposit_idx: DepositIdx,
        counterproof: G16ProofRaw,
        completed_signatures: CompletedSignatures,
        sighash: [u8; 32],
        tweak: Option<[u8; 32]>,
    ) -> Result<Option<Signature>, MosaicError>;

    /// Subscribe to mosaic events.
    async fn subscribe_events(&self) -> Subscription<MosaicEvent>;
}
