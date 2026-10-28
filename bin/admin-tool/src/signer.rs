//! Signing backends keep private material behind public-key and digest-signing operations.

use std::{fmt, fs::File, io::Read, path::Path};

use anyhow::{anyhow, ensure, Context, Result};
use bitcoin::secp256k1::{schnorr, Keypair, Message, XOnlyPublicKey, SECP256K1};
use zeroize::Zeroizing;

/// Async interface for file, S2, or HSM backends; signing uses the untweaked admin key.
pub(super) trait AdminSigner: Send + Sync {
    async fn public_key(&self) -> Result<XOnlyPublicKey>;

    async fn sign_digest(&self, digest: [u8; 32]) -> Result<schnorr::Signature>;
}

/// Existing private key file: 64 hex characters with optional surrounding whitespace.
pub(super) struct FileAdminSigner {
    /// Untweaked signing key, kept inside this backend.
    keypair: Keypair,
}

impl FileAdminSigner {
    pub(super) fn from_path(path: &Path) -> Result<Self> {
        // Bound the read; this backend never creates or rewrites the key file.
        let mut encoded = Zeroizing::new(String::new());
        File::open(path)?.take(257).read_to_string(&mut encoded)?;
        ensure!(
            encoded.len() <= 256 && encoded.trim().len() == 64,
            "admin key file must contain a valid private key as 64 hex characters"
        );

        let mut decoded = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(encoded.trim(), decoded.as_mut())
            .map_err(|_| anyhow!("invalid hex in admin key file"))?;
        let keypair = Keypair::from_seckey_slice(SECP256K1, decoded.as_ref())
            .context("invalid admin private key")?;

        Ok(Self { keypair })
    }
}

impl AdminSigner for FileAdminSigner {
    async fn public_key(&self) -> Result<XOnlyPublicKey> {
        Ok(self.keypair.x_only_public_key().0)
    }

    async fn sign_digest(&self, digest: [u8; 32]) -> Result<schnorr::Signature> {
        Ok(SECP256K1.sign_schnorr(&Message::from_digest(digest), &self.keypair))
    }
}

impl fmt::Debug for FileAdminSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileAdminSigner")
            .field("public_key", &self.keypair.x_only_public_key().0)
            .finish_non_exhaustive()
    }
}

impl Drop for FileAdminSigner {
    fn drop(&mut self) {
        self.keypair.non_secure_erase();
    }
}

#[cfg(test)]
mod tests;
