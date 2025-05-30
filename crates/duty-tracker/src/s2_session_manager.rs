//! This module implements a session state management system for musig sessions around a given
//! underlying SecretServiceClient.
use std::{collections::BTreeMap, sync::Arc};

use bdk_wallet::miniscript::ToPublicKey;
use bitcoin::{OutPoint, XOnlyPublicKey};
use musig2::{
    errors::{RoundContributionError, RoundFinalizeError},
    secp256k1::Message,
    LiftedSignature, PartialSignature, PubNonce,
};
use secret_service_client::{
    musig2::{Musig2FirstRound, Musig2SecondRound},
    SecretServiceClient,
};
use secret_service_proto::v1::{
    traits::{
        ClientError, Musig2Signer, Musig2SignerFirstRound, Musig2SignerSecondRound, SecretService,
    },
    wire::Musig2NewSessionError,
};
use strata_bridge_primitives::{operator_table::OperatorTable, scripts::taproot::TaprootWitness};
use thiserror::Error;
use tokio::sync::Mutex;
use tracing::{error, trace, warn};

#[derive(Debug, Clone)]
struct MusigSessionManagerState {
    /// Index for all of the active first round sessions.
    first_round_map: BTreeMap<OutPoint, Musig2FirstRound>,

    /// Index for all of the active second round sessions.
    second_round_map: BTreeMap<OutPoint, Musig2SecondRound>,
}

/// System for managing session state for musig sessions.
#[derive(Debug, Clone)]
pub struct MusigSessionManager {
    operator_table: OperatorTable,

    /// The underlying S2 client.
    pub s2_client: SecretServiceClient,

    state: Arc<Mutex<MusigSessionManagerState>>,
}

impl MusigSessionManager {
    /// Creates a new [`MusigSessionManager`] from a [`SecretServiceClient`].
    pub fn new(operator_table: OperatorTable, s2_client: SecretServiceClient) -> Self {
        MusigSessionManager {
            operator_table,
            s2_client,
            state: Arc::new(Mutex::new(MusigSessionManagerState {
                first_round_map: BTreeMap::new(),
                second_round_map: BTreeMap::new(),
            })),
        }
    }

    /// Given an [`OutPoint`] and a [`TaprootWitness]`, retrieves a `[PubNonce]` for that session.
    pub async fn get_nonce(
        &self,
        outpoint: OutPoint,
        taproot_witness: TaprootWitness,
    ) -> Result<PubNonce, MusigSessionErr> {
        trace!(%outpoint, "getting first round nonce");
        let first_round = self
            .s2_client
            .musig2_signer()
            .new_session(
                outpoint,
                self.operator_table
                    .btc_keys()
                    .into_iter()
                    .map(|x| x.to_x_only_pubkey())
                    .collect(),
                taproot_witness,
                outpoint.txid,
                outpoint.vout,
            )
            .await?
            .map_err(MusigSessionErr::SecretServiceNewSessionErr)?;

        let ours = first_round.our_nonce().await?;

        self.state
            .lock()
            .await
            .first_round_map
            .insert(outpoint, first_round);

        Ok(ours)
    }

    /// Loads a [`PubNonce`] into the signing session identified by an [`OutPoint`].
    pub async fn put_nonce(
        &self,
        outpoint: OutPoint,
        sender: XOnlyPublicKey,
        nonce: PubNonce,
    ) -> Result<(), MusigSessionErr> {
        trace!(%outpoint, "loading first round nonce");

        let mut state = self.state.lock().await;

        let first_round = state
            .first_round_map
            .get_mut(&outpoint)
            .ok_or(MusigSessionErr::NotFound(outpoint))
            .inspect_err(|e| {
                error!(%outpoint, %sender, %e, "first round missing");
            })?;

        Ok(first_round
            .receive_pub_nonces([(sender, nonce)].into_iter())
            .await??)
    }

    /// Given an [`OutPoint`] and the sighash for what is being signed, retrieves our MuSig2
    /// [`PartialSignature`].
    pub async fn get_partial(
        &self,
        outpoint: OutPoint,
        sighash: Message,
    ) -> Result<PartialSignature, MusigSessionErr> {
        trace!(%outpoint, "getting second round partial signature");

        let mut state = self.state.lock().await;

        if let Some(second_round) = state.second_round_map.get(&outpoint) {
            trace!(%outpoint, "getting our partial signature");

            return Ok(second_round.our_signature().await?);
        }

        if let Some(first_round) = state.first_round_map.remove(&outpoint) {
            let holdouts = first_round.holdouts().await?;
            trace!(%outpoint, ?holdouts, "fetched first round holdouts");

            if holdouts.is_empty() {
                trace!(%outpoint, "finalizing first round");
                let second_round = first_round.finalize(*sighash.as_ref()).await??;

                trace!(%outpoint, "getting our partial signature");
                let ours = second_round.our_signature().await?;

                trace!(%outpoint, "updating second round session with our signature");
                state.second_round_map.insert(outpoint, second_round);

                Ok(ours)
            } else {
                error!(?holdouts, "cannot proceed to second round with holdouts");

                state.first_round_map.insert(outpoint, first_round);
                Err(MusigSessionErr::Premature)
            }
        } else {
            warn!(%outpoint, "failed to get to second round, outpoint missing in first round");
            Err(MusigSessionErr::NotFound(outpoint))
        }
    }

    /// Loads a [`PartialSignature`] into the signing session identified by [`OutPoint`].
    pub async fn put_partial(
        &self,
        outpoint: OutPoint,
        sender: XOnlyPublicKey,
        partial: PartialSignature,
    ) -> Result<(), MusigSessionErr> {
        trace!(%outpoint, "loading second round partial signature");

        let mut state = self.state.lock().await;

        let second_round = state
            .second_round_map
            .get_mut(&outpoint)
            .ok_or(MusigSessionErr::NotFound(outpoint))
            .inspect_err(|e| {
                error!(%outpoint, %e, "second round missing");
            })?;
        Ok(second_round
            .receive_signatures([(sender, partial)].into_iter())
            .await??)
    }

    /// Finalizes the MuSig2 signing process and extract the final [`LiftedSignature`].
    pub async fn get_signature(
        &self,
        outpoint: OutPoint,
    ) -> Result<LiftedSignature, MusigSessionErr> {
        trace!(%outpoint, "getting aggregated signature");

        let mut state = self.state.lock().await;

        let second_round = state
            .second_round_map
            .remove(&outpoint)
            .ok_or(MusigSessionErr::NotFound(outpoint))
            .inspect_err(|e| {
                error!(%outpoint, %e, "second round missing");
            })?;
        if second_round.holdouts().await?.is_empty() {
            let sig = second_round.finalize().await??;
            Ok(sig)
        } else {
            state.second_round_map.insert(outpoint, second_round);
            Err(MusigSessionErr::Premature)
        }
    }

    /// Deletes all session state associated with the given [`OutPoint`].
    ///
    /// This clears any MuSig2 first round and second round sessions.
    pub async fn drop_session(&self, outpoint: OutPoint) {
        let mut state = self.state.lock().await;
        state.first_round_map.remove(&outpoint);
        state.second_round_map.remove(&outpoint);
    }
}

/// Error type that encapsulates all of the things that can go wrong with the Musig signing process.
#[derive(Debug, Error)]
pub enum MusigSessionErr {
    /// Errors from failed secret service requests
    #[error("secret service request failed with {0:?}")]
    SecretServiceClientErr(#[from] ClientError),

    /// Errors from failed secret service new session requests
    #[error("secret service failed to make new session {0:?}")]
    SecretServiceNewSessionErr(Musig2NewSessionError),

    /// Errors from failed round contributions
    #[error("secret service failed to contribute to round {0:?}")]
    SecretServiceRoundContributionErr(BTreeMap<XOnlyPublicKey, RoundContributionError>),

    /// Errors from failed round finalization
    #[error("secret service failed to finalize round {0:?}")]
    SecretServiceRoundFinalizeErr(#[from] RoundFinalizeError),

    /// Errors from calling later stages of the signing protocol prior to them being valid
    #[error("attempted to call signing method before it was valid")]
    Premature,

    /// Outpoint doesn't have an active session
    #[error("outpoint {0} does not have a valid and active session")]
    NotFound(OutPoint),
}

impl From<BTreeMap<XOnlyPublicKey, RoundContributionError>> for MusigSessionErr {
    fn from(value: BTreeMap<XOnlyPublicKey, RoundContributionError>) -> Self {
        Self::SecretServiceRoundContributionErr(value)
    }
}
