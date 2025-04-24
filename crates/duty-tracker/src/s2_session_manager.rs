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

/// System for managing session state for musig sessions.
#[derive(Debug, Clone)]
pub struct MusigSessionManager {
    operator_table: OperatorTable,

    /// The underlying S2 client.
    pub s2_client: SecretServiceClient,

    /// Index for all of the active first round sessions.
    first_round_map: Arc<Mutex<BTreeMap<OutPoint, Musig2FirstRound>>>,

    /// Index for all of the active second round sessions.
    second_round_map: Arc<Mutex<BTreeMap<OutPoint, Musig2SecondRound>>>,
}
impl MusigSessionManager {
    /// Creates a new [`MusigSessionManager`] from a [`SecretServiceClient`].
    pub fn new(operator_table: OperatorTable, s2_client: SecretServiceClient) -> Self {
        MusigSessionManager {
            operator_table,
            s2_client,
            first_round_map: Arc::new(Mutex::new(BTreeMap::new())),
            second_round_map: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Given an [`OutPoint`] and a [`TaprootWitness]`, retrieves a `[PubNonce]` for that session.
    pub async fn get_nonce(
        &self,
        outpoint: OutPoint,
        taproot_witness: TaprootWitness,
    ) -> Result<PubNonce, MusigSessionErr> {
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

        self.first_round_map
            .lock()
            .await
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
        let mut guard = self.first_round_map.lock().await;
        let first_round = guard.get_mut(&outpoint).ok_or(MusigSessionErr::NotFound)?;
        Ok(first_round.receive_pub_nonce(sender, nonce).await??)
    }

    /// Given an [`OutPoint`] and the sighash for what is being signed, retrieves our MuSig2
    /// [`PartialSignature`].
    pub async fn get_partial(
        &self,
        outpoint: OutPoint,
        sighash: Message,
    ) -> Result<PartialSignature, MusigSessionErr> {
        if let Some(second_round) = self.second_round_map.lock().await.get_mut(&outpoint) {
            Ok(second_round.our_signature().await?)
        } else {
            let mut first_guard = self.first_round_map.lock().await;
            if let Some(first_round) = first_guard.remove(&outpoint) {
                if first_round.holdouts().await?.is_empty() {
                    let second_round = first_round.finalize(*sighash.as_ref()).await??;
                    drop(first_guard);
                    let ours = second_round.our_signature().await?;
                    let mut second_guard = self.second_round_map.lock().await;
                    second_guard.insert(outpoint, second_round);
                    Ok(ours)
                } else {
                    first_guard.insert(outpoint, first_round);
                    drop(first_guard);
                    Err(MusigSessionErr::Premature)
                }
            } else {
                Err(MusigSessionErr::NotFound)
            }
        }
    }

    /// Loads a [`PartialSignature`] into the signing session identified by [`OutPoint`].
    pub async fn put_partial(
        &self,
        outpoint: OutPoint,
        sender: XOnlyPublicKey,
        partial: PartialSignature,
    ) -> Result<(), MusigSessionErr> {
        let mut guard = self.second_round_map.lock().await;
        let second_round = guard.get_mut(&outpoint).ok_or(MusigSessionErr::NotFound)?;
        Ok(second_round.receive_signature(sender, partial).await??)
    }

    /// Finalizes the MuSig2 signing process and extract the final [`LiftedSignature`].
    pub async fn get_signature(
        &self,
        outpoint: OutPoint,
    ) -> Result<LiftedSignature, MusigSessionErr> {
        let mut guard = self.second_round_map.lock().await;
        let second_round = guard.remove(&outpoint).ok_or(MusigSessionErr::NotFound)?;
        if second_round.holdouts().await?.is_empty() {
            let sig = second_round.finalize().await??;
            Ok(sig)
        } else {
            guard.insert(outpoint, second_round);
            drop(guard);
            Err(MusigSessionErr::Premature)
        }
    }

    /// Deletes all session state associated with the given [`OutPoint`].
    ///
    /// This clears any MuSig2 first round and second round sessions.
    pub async fn drop_session(&self, outpoint: OutPoint) {
        self.first_round_map.lock().await.remove(&outpoint);
        self.second_round_map.lock().await.remove(&outpoint);
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
    SecretServiceRoundContributionErr(#[from] RoundContributionError),

    /// Errors from failed round finalization
    #[error("secret service failed to finalize round {0:?}")]
    SecretServiceRoundFinalizeErr(#[from] RoundFinalizeError),

    /// Errors from calling later stages of the signing protocol prior to them being valid
    #[error("attempted to call signing method before it was valid")]
    Premature,

    /// Outpoint doesn't have an active session
    #[error("outpoint does not have a valid and active session")]
    NotFound,
}
