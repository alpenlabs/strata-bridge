//! Local signing with an existing admin private key file.

use std::{
    convert::Infallible,
    fmt,
    fs::File,
    io::{self, Read},
    path::Path,
};

use bitcoin::secp256k1::{schnorr, Keypair, Message, XOnlyPublicKey, SECP256K1};
use zeroize::Zeroizing;

use crate::AdminSigner;

/// Admin signer loaded from a file containing one 32-byte private key as 64 hex characters.
///
/// Leading and trailing whitespace are accepted. This is an existing, untweaked signing key,
/// not an operator seed or a BIP32 derivation. Loading never creates or rewrites the file.
pub struct FileAdminSigner {
    /// Untweaked admin key, kept inside this backend.
    keypair: Keypair,
}

impl FileAdminSigner {
    /// Reads an existing hex private key; file and decoded buffers are cleared on drop.
    pub fn from_path(path: &Path) -> Result<Self, FileSignerError> {
        let mut encoded = Zeroizing::new(String::new());
        // Bound the read even when an incorrect or unexpectedly large file is supplied.
        File::open(path)?.take(257).read_to_string(&mut encoded)?;
        if encoded.len() > 256 {
            return Err(FileSignerError::InvalidKey);
        }
        let encoded = encoded.trim();
        if encoded.len() != 64 {
            return Err(FileSignerError::InvalidKey);
        }
        let mut decoded = Zeroizing::new([0u8; 32]);
        hex::decode_to_slice(encoded, decoded.as_mut()).map_err(|_| FileSignerError::InvalidKey)?;
        let keypair = Keypair::from_seckey_slice(SECP256K1, decoded.as_ref())
            .map_err(|_| FileSignerError::InvalidKey)?;
        Ok(Self { keypair })
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

impl AdminSigner for FileAdminSigner {
    type Error = Infallible;

    async fn public_key(&self) -> Result<XOnlyPublicKey, Self::Error> {
        Ok(self.keypair.x_only_public_key().0)
    }

    async fn sign_digest(&self, digest: [u8; 32]) -> Result<schnorr::Signature, Self::Error> {
        Ok(SECP256K1.sign_schnorr(&Message::from_digest(digest), &self.keypair))
    }
}

/// Failure to load an existing admin private key, without including its contents in errors.
#[derive(Debug, thiserror::Error)]
pub enum FileSignerError {
    /// The file could not be opened or read as text.
    #[error("could not read admin private key file: {0}")]
    Io(#[from] io::Error),
    /// The file does not contain exactly one valid hex-encoded secp256k1 private key.
    #[error("admin key file must contain a valid private key as 64 hex characters")]
    InvalidKey,
}

#[cfg(test)]
mod tests {
    use std::{fs, io::Write};

    use super::*;

    #[tokio::test]
    async fn loads_existing_hex_key_and_signs_without_tweaking() {
        let encoded = format!("  {}\n", "01".repeat(32));
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(encoded.as_bytes()).unwrap();
        let signer = FileAdminSigner::from_path(file.path()).unwrap();
        let expected = Keypair::from_seckey_slice(SECP256K1, &[1; 32]).unwrap();
        let public_key = signer.public_key().await.unwrap();
        assert_eq!(public_key, expected.x_only_public_key().0);
        let digest = [42; 32];
        let signature = signer.sign_digest(digest).await.unwrap();
        SECP256K1
            .verify_schnorr(&signature, &Message::from_digest(digest), &public_key)
            .unwrap();
        assert_eq!(fs::read_to_string(file.path()).unwrap(), encoded);
        assert!(!format!("{signer:?}").contains(&"01".repeat(32)));
    }

    #[test]
    fn rejects_invalid_keys_without_exposing_the_contents() {
        for encoded in [
            "secret input".to_owned(),
            "00".repeat(32),
            "ff".repeat(32),
            "01".repeat(33),
            "g1".repeat(32),
            format!("{}{}extra", "01".repeat(32), " ".repeat(192)),
        ] {
            let mut file = tempfile::NamedTempFile::new().unwrap();
            file.write_all(encoded.as_bytes()).unwrap();
            let error = FileAdminSigner::from_path(file.path()).unwrap_err();
            assert!(matches!(error, FileSignerError::InvalidKey));
            assert!(!error.to_string().contains(&encoded));
        }
    }
}
