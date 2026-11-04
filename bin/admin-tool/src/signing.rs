//! Validate the claim connector and build the digest admins authorize.

use anyhow::{ensure, Context, Result};
use bitcoin::{
    hashes::sha256,
    hex::FromHex,
    secp256k1::{Message, SECP256K1},
    sighash::{Prevouts, SighashCache},
    taproot, Amount, Network, OutPoint, ScriptBuf, TapSighashType, Transaction, TxOut, Txid,
    XOnlyPublicKey,
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
    /// Bridge transaction template and validated connector used for witness assembly.
    burn: AdminBurnTx,
}

/// Assembled transaction and the admins whose signatures were included in its witness.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct AssembledBurn {
    /// Transaction ready for external funding.
    pub transaction: Transaction,
    /// Included admin indices in configured key order.
    pub admin_indices: Vec<usize>,
}

impl SigningRequest {
    pub(super) fn new(
        claim_txid: Txid,
        claim: &Transaction,
        params: SigningParams,
    ) -> Result<Self> {
        let (prevout, connector) = SigningRequest::validate_args(&claim_txid, claim, &params)?;

        // The bridge template fixes version 3, locktime zero, maximum sequence, and no annex.
        let tx = AdminBurnTx::new(AdminBurnData { claim_txid }, connector.clone());
        let signing_info = connector.get_signing_info_with_sighash_type(
            &mut SighashCache::new(tx.as_ref()),
            Prevouts::All(std::slice::from_ref(&prevout)),
            ClaimPayoutSpendPath::AdminBurn,
            0,
            ADMIN_SIGHASH_TYPE,
        );

        Ok(Self {
            claim_outpoint: OutPoint::new(claim_txid, ClaimTx::PAYOUT_VOUT),
            admin_pubkeys: params.admin_pubkeys,
            threshold: params.threshold,
            digest: *signing_info.sighash.as_ref(),
            burn: tx,
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

    /// Identifies each signer by verification and assembles the witness before external funding.
    pub(super) fn assemble(&self, encoded_signatures: &[String]) -> Result<AssembledBurn> {
        ensure!(
            encoded_signatures.len() >= self.threshold,
            "need at least {} distinct admin signatures",
            self.threshold
        );

        let message = Message::from_digest(self.digest);
        let mut signatures: Vec<AdminSignature> = Vec::with_capacity(encoded_signatures.len());
        for (position, encoded) in encoded_signatures.iter().enumerate() {
            let number = position + 1;
            let bytes = Vec::from_hex(encoded.trim())
                .with_context(|| format!("signature #{number}: invalid hex"))?;
            let signature = taproot::Signature::from_slice(&bytes)
                .with_context(|| format!("signature #{number}: invalid Taproot signature"))?;
            ensure!(
                signature.sighash_type == ADMIN_SIGHASH_TYPE,
                "signature #{number}: must use NONE | ANYONECANPAY (0x82)"
            );

            let pubkey_index = self
                .admin_pubkeys
                .iter()
                .position(|key| {
                    SECP256K1
                        .verify_schnorr(&signature.signature, &message, key)
                        .is_ok()
                })
                .with_context(|| {
                    format!(
                        "signature #{number}: does not verify against any admin key for this claim"
                    )
                })?;
            ensure!(
                !signatures
                    .iter()
                    .any(|signature| signature.pubkey_index == pubkey_index),
                "signature #{number}: duplicate admin signature (admin index {pubkey_index})"
            );

            signatures.push(AdminSignature {
                pubkey_index,
                signature,
            });
        }

        // Match the connector's threshold selection before reporting the included admins.
        signatures.sort_by_key(|signature| signature.pubkey_index);
        signatures.truncate(self.threshold);
        let admin_indices = signatures
            .iter()
            .map(|signature| signature.pubkey_index)
            .collect();

        // Core wallet funding requires an output; NONE lets the funder change outputs later.
        let mut burn = self.burn.clone();
        burn.push_output(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new_op_return([]),
        });

        Ok(AssembledBurn {
            transaction: burn.finalize_partial(signatures),
            admin_indices,
        })
    }

    /// Signs with the identified admin key and verifies the backend's result before export.
    pub(super) async fn sign_and_verify(
        &self,
        signer: &impl AdminSigner,
        public_key: XOnlyPublicKey,
    ) -> Result<taproot::Signature> {
        ensure!(
            self.admin_pubkeys.contains(&public_key),
            "signer public key {public_key} is not in the admin set"
        );

        let signature = signer
            .sign_digest(self.digest)
            .await
            .context("admin signer failed")?;
        SECP256K1
            .verify_schnorr(&signature, &Message::from_digest(self.digest), &public_key)
            .context("admin signer returned an invalid signature")?;

        Ok(taproot::Signature {
            signature,
            sighash_type: ADMIN_SIGHASH_TYPE,
        })
    }

    fn validate_args(
        claim_txid: &Txid,
        claim: &Transaction,
        params: &SigningParams,
    ) -> Result<(TxOut, ClaimPayoutConnector)> {
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
            claim.compute_txid() == *claim_txid,
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
        Ok((prevout.clone(), connector))
    }
}

#[cfg(test)]
mod tests;
