//! TOML-driven config schema for the bridge-counterproof host.

use std::fmt;
#[cfg(feature = "sp1")]
use std::path::PathBuf;

use k256::schnorr::SigningKey;
use serde::{Deserialize, Serialize};

/// Backend selection for a bridge-counterproof host.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ProofBackendConfig {
    /// SP1 backend. Loads the guest ELF from disk at startup.
    #[cfg(feature = "sp1")]
    Sp1 {
        /// Absolute path to the compiled SP1 guest ELF.
        elf_path: PathBuf,
    },

    /// Native backend. The signing key fixes the predicate identity of the host:
    /// the verifying key derived from it is what gets packed into the host's `PredicateKey`.
    Native {
        /// Schnorr signing key used by the native host to sign its produced proofs;
        /// the derived verifying key is the host's predicate identity.
        #[serde(with = "hex_signing_key")]
        schnorr_signing_key: SigningKey,
    },
}

impl fmt::Debug for ProofBackendConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "sp1")]
            Self::Sp1 { elf_path } => f.debug_struct("Sp1").field("elf_path", elf_path).finish(),
            Self::Native { .. } => f
                .debug_struct("Native")
                .field("schnorr_signing_key", &"<redacted>")
                .finish(),
        }
    }
}

mod hex_signing_key {
    use k256::schnorr::SigningKey;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub(super) fn serialize<S: Serializer>(key: &SigningKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(key.to_bytes()))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<SigningKey, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = hex::decode(&s).map_err(D::Error::custom)?;
        SigningKey::from_bytes(&bytes).map_err(D::Error::custom)
    }
}
