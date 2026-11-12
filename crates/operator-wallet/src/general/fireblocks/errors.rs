//! The errors of building a Fireblocks signer, of a signing request, and of the startup check.

use bdk_wallet::bitcoin::secp256k1::PublicKey;
use thiserror::Error;

use super::raw::MAX_RAW_MESSAGES;

/// A [`FireblocksSigner`](super::FireblocksSigner) could not be built from its configuration.
#[derive(Debug, Error)]
pub enum FireblocksInitError {
    /// The API secret is not a valid RSA PEM.
    #[error("invalid Fireblocks API secret (RSA PEM): {0}")]
    SigningKey(String),
    /// `base_url` is not a bare `https` origin. The requests carry the API key and a signed JWT,
    /// and each request appends its own `/v1` path. The error holds no copy of the value, which
    /// can carry a credential.
    #[error("base_url must be a bare https origin such as https://api.fireblocks.io")]
    InvalidBaseUrl,
    /// The HTTP client could not be built.
    #[error("building HTTP client: {0}")]
    HttpClient(String),
}

/// A signature could not be obtained from Fireblocks.
#[derive(Debug, Error)]
pub enum FireblocksError {
    /// JWT construction failed.
    #[error("jwt: {0}")]
    Jwt(String),
    /// HTTP transport error talking to the Fireblocks API.
    #[error("http: {0}")]
    Http(String),
    /// Fireblocks returned a non-success status.
    #[error("fireblocks api: {status}: {body}")]
    Api {
        /// The HTTP status code.
        status: u16,
        /// The response body.
        body: String,
    },
    /// A response body could not be deserialized into the expected shape.
    #[error("decode response: {0}")]
    Decode(String),
    /// A signing request could not be built.
    #[error("sign request: {0}")]
    SignRequest(String),
    /// A RAW transaction reached a state that can never produce its signatures.
    #[error("raw-sign transaction {tx_id} failed: {reason}")]
    RequestFailed {
        /// The Fireblocks transaction id.
        tx_id: String,
        /// The status, and the substatus when Fireblocks gives one.
        reason: String,
    },
    /// Witness assembly from a returned signature failed.
    #[error("witness: {0}")]
    Witness(String),
    /// A signing request did not reach a usable signed state within the allotted time.
    #[error("signing timed out for tx {0}")]
    SigningTimeout(String),
    /// The walk through the dead requests of a sighash set did not finish in time.
    #[error("no live raw-sign request found for {digest} in time")]
    SearchTimeout {
        /// The hash part of the request id.
        digest: String,
    },
    /// A transaction has more vault inputs than one RAW request can sign. The vault needs
    /// consolidation, or larger outputs. The error is transient like the others because the next
    /// selection can pick fewer, larger inputs; the operator action is what makes that likely.
    #[error("{count} vault inputs to sign; one RAW request takes at most {MAX_RAW_MESSAGES}")]
    TooManyInputs {
        /// The number of inputs that the transaction spends from the vault.
        count: usize,
    },
}

impl FireblocksError {
    /// Whether this failure says that the API is unavailable, and not that a request was wrong.
    pub(super) const fn is_outage(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::Api { status, .. } => *status == 429 || *status >= 500,
            _ => false,
        }
    }
}

/// The startup check of a [`FireblocksSigner`](super::FireblocksSigner) did not pass.
#[derive(Debug, Error)]
pub enum StartupCheckError {
    /// Fireblocks reports a public key for the vault address that differs from the configured
    /// `vault_pubkey`.
    #[error("vault_pubkey is not the key of the vault address, which is {reported}")]
    VaultKeyMismatch {
        /// The key that Fireblocks reports.
        reported: PublicKey,
    },
    /// The public key of the vault address could not be read.
    #[error("reading the vault key: {0}")]
    KeyLookup(FireblocksError),
    /// The vault could not sign the test digest.
    #[error("signing the test digest: {0}")]
    Signing(FireblocksError),
    /// The vault store could not be read. This read decides which checks run, so it comes before
    /// the read in [`OperatorWallet::load_or_create`](crate::OperatorWallet::load_or_create).
    #[error("reading the vault store: {0}")]
    Store(Box<dyn std::error::Error + Send + Sync>),
}
