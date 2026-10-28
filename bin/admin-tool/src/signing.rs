//! Validate the claim connector and build the digest admins authorize.

use anyhow::{ensure, Context, Result};
use bitcoin::{
    hashes::sha256,
    secp256k1::{Message, SECP256K1},
    sighash::{Prevouts, SighashCache},
    taproot, Network, OutPoint, TapSighashType, Transaction, Txid, XOnlyPublicKey,
};
use strata_bridge_connectors::{
    prelude::{AdminSignature, ClaimPayoutConnector, ClaimPayoutSpendPath},
    Connector,
};
use strata_bridge_tx_graph::transactions::prelude::{AdminBurnData, AdminBurnTx, ClaimTx};

use crate::signer::AdminSigner;

/// Allows a publisher to add funding inputs and choose outputs after admins sign.
pub(super) const ADMIN_SIGHASH_TYPE: TapSighashType = TapSighashType::NonePlusAnyoneCanPay;

/// Public parameters used to reconstruct the claim's payout connector.
#[derive(Debug, Clone)]
pub(super) struct SigningParams {
    /// Bitcoin network, checked against the node by the caller.
    pub network: Network,
    /// Untweaked aggregate federation key.
    pub n_of_n_pubkey: XOnlyPublicKey,
    /// Admin public keys in script order.
    pub admin_pubkeys: Vec<XOnlyPublicKey>,
    /// Required number of distinct admin signatures.
    pub threshold: usize,
    /// Public SHA-256 hash of the operator's unstaking preimage.
    pub unstaking_hash: sha256::Hash,
}

/// Validated connector and signing digest; chain status is checked by the caller.
#[derive(Debug)]
pub(super) struct SigningRequest {
    /// Claim payout output (`claim_txid:1`) authorized for spending.
    claim_outpoint: OutPoint,
    /// Admin public keys in the validated connector's script order.
    admin_pubkeys: Vec<XOnlyPublicKey>,
    /// Number of distinct admin signatures required by the admin script.
    threshold: usize,
    /// Taproot transaction signing hash using `SIGHASH_NONE | SIGHASH_ANYONECANPAY`.
    digest: [u8; 32],
}

impl SigningRequest {
    pub(super) fn new(
        claim_txid: Txid,
        claim: &Transaction,
        params: SigningParams,
    ) -> Result<Self> {
        ensure!(
            !params.admin_pubkeys.is_empty(),
            "admin set must not be empty"
        );
        ensure!(
            params.threshold > 0 && params.threshold <= params.admin_pubkeys.len(),
            "admin threshold must be between 1 and the number of admin keys"
        );

        for (index, key) in params.admin_pubkeys.iter().enumerate() {
            ensure!(
                !params.admin_pubkeys[..index].contains(key),
                "duplicate admin public key: {key}"
            );
        }

        ensure!(
            claim.compute_txid() == claim_txid,
            "supplied claim transaction does not match the requested txid"
        );
        let prevout = claim
            .output
            .get(ClaimTx::PAYOUT_VOUT as usize)
            .context("claim transaction has no payout output at index 1")?;

        let connector = ClaimPayoutConnector::new(
            params.network,
            params.n_of_n_pubkey,
            params.admin_pubkeys.clone(),
            params.threshold,
            params.unstaking_hash,
        );
        ensure!(
            prevout.script_pubkey == connector.script_pubkey(),
            "reconstructed payout connector does not match claim output 1"
        );
        ensure!(
            prevout.value == connector.value(),
            "claim payout value is {}, expected {}",
            prevout.value,
            connector.value()
        );

        // The bridge template fixes version 3, locktime zero, maximum sequence, and no annex.
        let tx = AdminBurnTx::new(AdminBurnData { claim_txid }, connector.clone());
        let signing_info = connector.get_signing_info_with_sighash_type(
            &mut SighashCache::new(tx.as_ref()),
            Prevouts::All(std::slice::from_ref(prevout)),
            ClaimPayoutSpendPath::AdminBurn,
            0,
            ADMIN_SIGHASH_TYPE,
        );

        Ok(Self {
            claim_outpoint: OutPoint::new(claim_txid, ClaimTx::PAYOUT_VOUT),
            admin_pubkeys: params.admin_pubkeys,
            threshold: params.threshold,
            digest: *signing_info.sighash.as_ref(),
        })
    }

    pub(super) const fn claim_outpoint(&self) -> OutPoint {
        self.claim_outpoint
    }

    pub(super) fn admin_pubkeys(&self) -> &[XOnlyPublicKey] {
        &self.admin_pubkeys
    }

    pub(super) const fn threshold(&self) -> usize {
        self.threshold
    }

    pub(super) const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    /// Signs with the identified admin key and verifies the backend's result before export.
    pub(super) async fn sign(
        &self,
        signer: &impl AdminSigner,
        public_key: XOnlyPublicKey,
    ) -> Result<AdminSignature> {
        let pubkey_index = self
            .admin_pubkeys
            .iter()
            .position(|key| *key == public_key)
            .with_context(|| format!("signer public key {public_key} is not in the admin set"))?;

        let signature = signer
            .sign_digest(self.digest)
            .await
            .context("admin signer failed")?;
        SECP256K1
            .verify_schnorr(&signature, &Message::from_digest(self.digest), &public_key)
            .context("admin signer returned an invalid signature")?;

        Ok(AdminSignature {
            pubkey_index,
            signature: taproot::Signature {
                signature,
                sighash_type: ADMIN_SIGHASH_TYPE,
            },
        })
    }
}

#[cfg(test)]
mod tests;
