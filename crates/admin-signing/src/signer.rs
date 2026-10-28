//! Signing backend interface; private keys remain inside the implementation.

use std::{error::Error, future::Future};

use bitcoin::secp256k1::{schnorr, XOnlyPublicKey};

/// Backend that identifies an admin key and signs a digest without exporting private material.
///
/// Signatures use the untweaked admin key because the key appears inside a Taproot script.
/// Asynchronous methods allow local files, remote signers, and hardware to share this interface.
pub trait AdminSigner: Send + Sync {
    /// Backend-specific failure.
    type Error: Error + Send + Sync + 'static;

    /// Returns the BIP-340 public key of the admin signing key.
    fn public_key(&self) -> impl Future<Output = Result<XOnlyPublicKey, Self::Error>> + Send;

    /// Signs the supplied 32-byte digest with the untweaked admin key.
    fn sign_digest(
        &self,
        digest: [u8; 32],
    ) -> impl Future<Output = Result<schnorr::Signature, Self::Error>> + Send;
}

/// Failure to obtain a valid signature from an authorized admin.
#[derive(Debug, thiserror::Error)]
pub enum SigningError<E: Error + 'static> {
    /// The signer public key does not belong to the configured admin set.
    #[error("signer public key {0} is not in the admin set")]
    UnauthorizedSigner(XOnlyPublicKey),
    /// The signer could not identify its key or sign the digest.
    #[error("admin signer failed: {0}")]
    Backend(#[source] E),
    /// The returned signature does not verify for the request and the advertised public key.
    #[error("admin signer returned an invalid signature: {0}")]
    InvalidSignature(#[source] bitcoin::secp256k1::Error),
}
