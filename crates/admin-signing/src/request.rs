//! Construction and validation of the admin-burn signing payload.

use bitcoin::{
    hashes::sha256,
    secp256k1::{Message, SECP256K1},
    sighash::{Prevouts, SighashCache},
    taproot, Amount, Network, OutPoint, TapSighashType, Transaction, Txid, XOnlyPublicKey,
};
use strata_bridge_connectors::{
    prelude::{AdminSignature, ClaimPayoutConnector, ClaimPayoutSpendPath},
    Connector,
};
use strata_bridge_tx_graph::transactions::prelude::{AdminBurnData, AdminBurnTx, ClaimTx};

use crate::{AdminSigner, SigningError};

/// Allows a publisher to add funding inputs and choose outputs after admins sign.
pub const ADMIN_SIGHASH_TYPE: TapSighashType = TapSighashType::NonePlusAnyoneCanPay;

/// Public parameters needed to reconstruct a claim's payout connector.
#[derive(Debug, Clone)]
pub struct AdminSigningParams {
    /// Network used for connector construction; chain identity is checked by the caller.
    pub network: Network,
    /// Untweaked aggregate federation key, not the tweaked Taproot output key.
    pub n_of_n_pubkey: XOnlyPublicKey,
    /// Admin public keys in script order.
    pub admin_pubkeys: Vec<XOnlyPublicKey>,
    /// Required number of distinct admin signatures.
    pub threshold: usize,
    /// Public SHA-256 hash of the operator's unstaking preimage.
    pub unstaking_hash: sha256::Hash,
}

/// A validated claim connector and the deterministic digest admins authorize.
///
/// Construction fixes version 3, locktime zero, maximum input sequence, no outputs, and no
/// annex through the existing [`AdminBurnTx`] template. The sighash does not commit to other
/// inputs or outputs; a publisher can add those later without changing the admin digest.
#[derive(Debug, Clone)]
pub struct AdminSigningRequest {
    /// Claim payout output (`claim_txid:1`) authorized for spending.
    claim_outpoint: OutPoint,
    /// Admin public keys in the validated connector's script order.
    admin_pubkeys: Vec<XOnlyPublicKey>,
    /// Number of distinct admin signatures required by the admin script.
    threshold: usize,
    /// Taproot transaction signing hash using `SIGHASH_NONE | SIGHASH_ANYONECANPAY`.
    digest: [u8; 32],
}

impl AdminSigningRequest {
    /// Validates the public parameters and claim output, then computes the signing digest.
    ///
    /// The supplied transaction must hash to `claim_txid`, and its payout output must match
    /// both the reconstructed script and amount. Confirmation and unspent status are the
    /// caller's responsibility; no RPC or wallet access happens here.
    pub fn new(
        claim_txid: Txid,
        claim: &Transaction,
        params: AdminSigningParams,
    ) -> Result<Self, RequestError> {
        if params.admin_pubkeys.is_empty() {
            return Err(RequestError::EmptyAdminSet);
        }
        if params.threshold == 0 || params.threshold > params.admin_pubkeys.len() {
            return Err(RequestError::InvalidThreshold);
        }
        for (index, key) in params.admin_pubkeys.iter().enumerate() {
            if params.admin_pubkeys[..index].contains(key) {
                return Err(RequestError::DuplicateAdminKey(*key));
            }
        }
        if claim.compute_txid() != claim_txid {
            return Err(RequestError::ClaimTxidMismatch);
        }
        let prevout = claim
            .output
            .get(ClaimTx::PAYOUT_VOUT as usize)
            .ok_or(RequestError::MissingPayoutOutput)?;
        let connector = ClaimPayoutConnector::new(
            params.network,
            params.n_of_n_pubkey,
            params.admin_pubkeys.clone(),
            params.threshold,
            params.unstaking_hash,
        );
        if prevout.script_pubkey != connector.script_pubkey() {
            return Err(RequestError::PayoutScriptMismatch);
        }
        if prevout.value != connector.value() {
            return Err(RequestError::PayoutValueMismatch {
                expected: connector.value(),
                actual: prevout.value,
            });
        }

        let tx = AdminBurnTx::new(AdminBurnData { claim_txid }, connector.clone());
        let prevouts = [prevout.clone()];
        let signing_info = connector.get_signing_info_with_sighash_type(
            &mut SighashCache::new(tx.as_ref()),
            Prevouts::All(&prevouts),
            ClaimPayoutSpendPath::AdminBurn,
            0,
            ADMIN_SIGHASH_TYPE,
        );

        Ok(Self {
            claim_outpoint: OutPoint {
                txid: claim_txid,
                vout: ClaimTx::PAYOUT_VOUT,
            },
            admin_pubkeys: params.admin_pubkeys,
            threshold: params.threshold,
            digest: *signing_info.sighash.as_ref(),
        })
    }

    /// Returns the exact claim payout outpoint being authorized.
    pub const fn claim_outpoint(&self) -> OutPoint {
        self.claim_outpoint
    }

    /// Returns the ordered admin keys committed to by the validated connector.
    pub fn admin_pubkeys(&self) -> &[XOnlyPublicKey] {
        &self.admin_pubkeys
    }

    /// Returns the required number of admin signatures.
    pub const fn threshold(&self) -> usize {
        self.threshold
    }

    /// Returns the deterministic Taproot script-spend digest for this authorization.
    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Obtains and verifies one authorized admin's signature, including its sighash type.
    ///
    /// The backend is only asked to sign after its public key matches the admin set. Returned
    /// signatures are verified before export so a backend cannot silently sign a different
    /// digest or use a different key.
    pub async fn sign<S: AdminSigner>(
        &self,
        signer: &S,
    ) -> Result<AdminSignature, SigningError<S::Error>> {
        let public_key = signer.public_key().await.map_err(SigningError::Backend)?;
        let pubkey_index = self
            .admin_pubkeys
            .iter()
            .position(|key| *key == public_key)
            .ok_or(SigningError::UnauthorizedSigner(public_key))?;
        let signature = signer
            .sign_digest(self.digest)
            .await
            .map_err(SigningError::Backend)?;
        SECP256K1
            .verify_schnorr(&signature, &Message::from_digest(self.digest), &public_key)
            .map_err(SigningError::InvalidSignature)?;

        Ok(AdminSignature {
            pubkey_index,
            signature: taproot::Signature {
                signature,
                sighash_type: ADMIN_SIGHASH_TYPE,
            },
        })
    }
}

/// Invalid parameters or claim data supplied for admin signing.
#[derive(Debug, thiserror::Error)]
pub enum RequestError {
    /// No admin public keys were supplied.
    #[error("admin set must not be empty")]
    EmptyAdminSet,
    /// The threshold is zero or exceeds the number of admin keys.
    #[error("admin threshold must be between 1 and the number of admin keys")]
    InvalidThreshold,
    /// The same admin key appears more than once.
    #[error("duplicate admin public key: {0}")]
    DuplicateAdminKey(XOnlyPublicKey),
    /// The supplied transaction does not match the requested claim txid.
    #[error("supplied claim transaction does not match the requested txid")]
    ClaimTxidMismatch,
    /// The claim does not contain the payout output.
    #[error("claim transaction has no payout output at index 1")]
    MissingPayoutOutput,
    /// Connector parameters do not reconstruct the claim's payout script.
    #[error("reconstructed payout connector does not match claim output 1")]
    PayoutScriptMismatch,
    /// The claim payout amount differs from the bridge connector's amount.
    #[error("claim payout value is {actual}, expected {expected}")]
    PayoutValueMismatch {
        /// Amount defined by the reconstructed bridge connector.
        expected: Amount,
        /// Amount actually present in the supplied claim output.
        actual: Amount,
    },
}
