//! Custody of the general funds in a Fireblocks vault.
//!
//! Fireblocks only signs. The node tracks the vault script with a watch-only BDK wallet, so
//! UTXOs, confirmations, and mempool state all come from the operator's own bitcoind, and lease
//! logic is the same as under secret-service custody.
//!
//! ## What the vault holds
//!
//! The default P2WPKH address of a vault account holds:
//! - the funds that the general wallet spends: withdrawal fronting, stake funding, claim refills
//!   and CPFP fees,
//! - the change of those spends, and
//! - each payout paid to [`OperatorWallet::payout_descriptor`](crate::OperatorWallet), which is the
//!   descriptor that the node gossips for a withdrawal or an unstake.
//!
//! The vault holds no other funds. Secret-service holds:
//! - every bridge protocol key, including the keys of anchors and presigned transactions,
//! - the reserved wallet key, and
//! - the general key. The covenant `payout_descriptor` in the params is P2TR, so a presigned-graph
//!   payout pays `tr(general key)`. That output is not in the vault and the watch-only wallet does
//!   not track it. [`FireblocksSigner`] returns `None` for such an input, and the caller signs it
//!   through secret-service.
//!
//! ## Why RAW signing
//!
//! Fireblocks can produce a BTC transaction two ways. The `TRANSFER` + `inputsSelection`
//! flow has Fireblocks build *and broadcast* its own transaction, which is unusable here: a CPFP
//! child spends a foreign Taproot anchor, must be v3/TRUC, has exact outputs, and goes out in a
//! package with its parent. So the vault signer uses **`RAW` signing**: the composer builds the
//! unsigned transaction, and this module sends the sighashes to Fireblocks for ECDSA signing and
//! assembles the witnesses.
//!
//! A RAW request carries digests only, so a policy rule cannot inspect what it approves. The
//! vault needs an auto-approve rule: a request that waits for a human past the signing limit is
//! cancelled.
//!
//! Fireblocks BTC is ECDSA secp256k1, so vault addresses are **P2WPKH**; funding witnesses are
//! `[DER-sig + SIGHASH_ALL byte, compressed pubkey]`.
//!
//! ## Request identity
//!
//! A retry of an unchanged transaction must not start a second MPC run while a first one can still
//! finish. The `externalTxId` of a request is therefore `<hash>-<generation>`, where `hash` is the
//! SHA-256 of the sorted sighashes. Fireblocks rejects a repeated id and keeps the request, so a
//! failed create looks up the id and polls the request that it finds. This covers a restart, a
//! create whose response was lost, and a give-up whose cancel failed.
//!
//! A give-up cancels the request, because the next attempt often signs other digests: the fee rate
//! moves. An id stays taken after its request ends, so a sighash set moves to the next generation
//! when it finds a request that ended: `REJECTED`, `BLOCKED`, `FAILED`, `CANCELLED` or `TIMEOUT`.
//! Fireblocks holds this record, so the node persists no counter. A policy refusal therefore costs
//! one refused request per retry of the duty, and a corrected policy applies at the next retry.
//!
//! `CANCELLED` is a dead request, whoever cancelled it. The vendor gives a cancel from the node and
//! a cancel from the console one substatus, `CANCELLED_BY_USER`, so a cancel by a person does not
//! stop the node.
//!
//! ## Startup check
//!
//! [`CheckedVault::check`] gives the value that
//! [`GeneralCustody::Fireblocks`](crate::GeneralCustody::Fireblocks) requires. A wrong
//! `vault_pubkey` would otherwise send change and payouts to a script that the vault cannot sign
//! for. See that function for the checks.
//!
//! ## Auth
//!
//! Every request carries `X-API-Key: <api key>` and `Authorization: Bearer <JWT>`, where the
//! JWT is RS256-signed with the operator's Fireblocks API secret (an RSA private key) and
//! carries `{ uri, nonce, iat, exp, sub = api key, bodyHash = SHA256(raw body) }`.

mod auth;
mod dto;
mod sign;

use std::{
    collections::{HashMap, HashSet},
    fmt,
    str::FromStr,
    sync::Arc,
    time::{Duration, Instant},
};

use bdk_wallet::{
    bitcoin::{secp256k1::PublicKey, CompressedPublicKey, ScriptBuf, Transaction, TxOut, Witness},
    descriptor,
    descriptor::ExtendedDescriptor,
    miniscript,
};
use reqwest::Method;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::persist::WalletStore;

/// The most messages that Fireblocks accepts in one RAW request. One message signs one input.
const MAX_RAW_MESSAGES: usize = 127;
/// The self-test digest is the SHA-256 of this tag. A BIP-143 sighash is a double SHA-256, so it
/// can equal this digest only if an inner hash equals the tag, and the tag is not 32 bytes long.
/// The signature that the self-test obtains therefore authorizes no spend.
const SELF_TEST_TAG: &[u8] = b"strata-bridge/operator-wallet/fireblocks/self-test";
/// How often to poll a RAW-signing transaction for completion. Tests poll fast against a mock
/// server; the production value is not exercised by a test.
const SIGN_POLL_INTERVAL: Duration = if cfg!(test) {
    Duration::from_millis(5)
} else {
    Duration::from_secs(2)
};
/// The limit on one wait for signatures. It sits above the MPC latency of an auto-approved
/// request. Each wait polls at least once, and a poll error does not end it: the request exists on
/// the server, so an API blip must not cost its MPC run. The deadline is read after each poll, so a
/// stalled signer costs this limit plus one
/// [`HTTP_REQUEST_TIMEOUT`] and one more for the cancel, and a batch of bumps pays that per parent.
const SIGN_MAX_DURATION: Duration = Duration::from_secs(180);
/// Per-request HTTP timeout. Without it a hung Fireblocks endpoint would stall a request
/// indefinitely: a hang is not an `Err`, and the deadline is read between polls, so it could wedge
/// the signing loop past [`SIGN_MAX_DURATION`]. Kept comfortably above normal latency but bounded.
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Connection + identity configuration for a Fireblocks BTC vault account.
pub struct FireblocksConfig {
    /// API host root, **without** the `/v1` path segment, e.g. `https://api.fireblocks.io`.
    /// Requests append `/v1/<path>` themselves so the JWT `uri` claim and the request URL
    /// stay in lockstep. [`FireblocksSigner::new`] rejects anything but a bare `https` origin.
    pub base_url: String,
    /// Fireblocks API key (sent as the `X-API-Key` header).
    pub api_key: String,
    /// Vault account id holding the BTC asset.
    pub vault_account_id: String,
    /// Asset id for the network: `BTC` on mainnet, and on a test network the id that the vault
    /// shows. The vendor gives no fixed id per test network.
    pub asset_id: String,
    /// Public key of the default address of the vault account. It defines the P2WPKH script that
    /// the node tracks, and that script is the operator's receive and change address.
    /// [`CheckedVault::check`] rejects a key that the vault does not hold.
    pub vault_pubkey: PublicKey,
}

impl fmt::Debug for FireblocksConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact the API key; everything else is non-secret operational config.
        f.debug_struct("FireblocksConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .field("vault_account_id", &self.vault_account_id)
            .field("asset_id", &self.asset_id)
            .field("vault_pubkey", &self.vault_pubkey)
            .finish()
    }
}

/// A [`FireblocksSigner`] could not be built from its configuration.
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
    const fn is_outage(&self) -> bool {
        match self {
            Self::Http(_) => true,
            Self::Api { status, .. } => *status == 429 || *status >= 500,
            _ => false,
        }
    }
}

/// The startup check of a [`FireblocksSigner`] did not pass.
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

/// The client of a Fireblocks vault. It signs inputs that spend the vault script.
///
/// A caller takes a clone from the wallet and holds no wallet lock while it waits for a signature.
/// [`GeneralSigner`](crate::general::GeneralSigner) holds this type by value, so the `Arc`s keep
/// that enum in the limits of `clippy::large_enum_variant`.
#[derive(Clone)]
pub struct FireblocksSigner {
    config: Arc<FireblocksConfig>,
    http: reqwest::Client,
    /// RS256 signing key derived from the operator's Fireblocks API secret. Used to mint the
    /// per-request JWT.
    signing_key: Arc<jsonwebtoken::EncodingKey>,
    /// The P2WPKH script of [`FireblocksConfig::vault_pubkey`]. This signer signs only inputs
    /// that spend it.
    script_pubkey: ScriptBuf,
    /// The first generation that a request for a sighash set (by digest) can still take, as this
    /// process last saw it. Every attempt would otherwise walk the ended generations from zero,
    /// two calls each, against the signing deadline. The map lives for the process; a restart
    /// walks once more.
    generations: Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
}

impl fmt::Debug for FireblocksSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FireblocksSigner")
            .field("config", &self.config)
            .field("signing_key", &"<redacted>")
            .field("script_pubkey", &self.script_pubkey)
            .finish()
    }
}

/// Returns the origin of `base_url`, which must be a bare `https` origin. `http` would send
/// credentials in cleartext, and a path would break the match of the request path and the JWT `uri`
/// claim.
fn parse_base_url(base_url: &str) -> Result<String, FireblocksInitError> {
    let url = reqwest::Url::parse(base_url).map_err(|_| FireblocksInitError::InvalidBaseUrl)?;
    let bare = url.scheme() == "https"
        && url.path() == "/"
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none();
    if !bare {
        return Err(FireblocksInitError::InvalidBaseUrl);
    }
    Ok(url.origin().ascii_serialization())
}

impl FireblocksSigner {
    /// Builds a signer from `config` and the operator's API secret (`api_secret_pem`, an RSA
    /// private key in PEM form used to sign request JWTs). Performs no network I/O.
    pub fn new(
        config: FireblocksConfig,
        api_secret_pem: &[u8],
    ) -> Result<Self, FireblocksInitError> {
        let base_url = parse_base_url(&config.base_url)?;
        Self::build(FireblocksConfig { base_url, ..config }, api_secret_pem)
    }

    /// Builds a signer on a `base_url` with no trailing slash. It is separate from [`Self::new`]
    /// because a mock server speaks plain HTTP, and the two differ by that one parse.
    fn build(config: FireblocksConfig, api_secret_pem: &[u8]) -> Result<Self, FireblocksInitError> {
        let signing_key = jsonwebtoken::EncodingKey::from_rsa_pem(api_secret_pem)
            .map_err(|e| FireblocksInitError::SigningKey(e.to_string()))?;

        let script_pubkey =
            ScriptBuf::new_p2wpkh(&CompressedPublicKey(config.vault_pubkey).wpubkey_hash());

        // A redirect target would receive the API key and a JWT, and it is not the host that the
        // operator configured. A 3xx response surfaces as an API error.
        let http = reqwest::Client::builder()
            .timeout(HTTP_REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|e| FireblocksInitError::HttpClient(e.to_string()))?;

        Ok(Self {
            config: Arc::new(config),
            http,
            signing_key: Arc::new(signing_key),
            script_pubkey,
            generations: Arc::default(),
        })
    }

    /// Issues an authenticated request to `subpath` and deserializes the JSON response into
    /// `T`. `body` is the request body (the same bytes are hashed into the JWT), or `None` for a
    /// request with no body.
    ///
    /// Non-2xx responses surface as [`FireblocksError::Api`] carrying the status + body;
    /// deserialization failures as [`FireblocksError::Decode`].
    async fn signed_request<T: DeserializeOwned>(
        &self,
        method: Method,
        subpath: &str,
        body: Option<&str>,
    ) -> Result<T, FireblocksError> {
        // The JWT `uri` claim and the request URL share one string, so they cannot drift apart.
        let uri = format!("/v1{subpath}");
        let url = format!("{}{uri}", self.config.base_url);
        let body_bytes = body.map_or(&b""[..], str::as_bytes);
        let jwt = auth::build_jwt(&uri, body_bytes, &self.config.api_key, &self.signing_key)?;

        let mut req = self
            .http
            .request(method, &url)
            .header("X-API-Key", &self.config.api_key)
            .bearer_auth(jwt);
        if let Some(body) = body {
            req = req
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_string());
        }

        let resp = req
            .send()
            .await
            .map_err(|e| FireblocksError::Http(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| FireblocksError::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(FireblocksError::Api {
                status: status.as_u16(),
                body: text,
            });
        }
        serde_json::from_str(&text)
            .map_err(|e| FireblocksError::Decode(format!("{e}; body={text}")))
    }

    /// Signs `sighashes` via a Fireblocks `RAW` transaction: finds or creates the request of this
    /// sighash set, then polls it until the signatures are available (or it fails / times out).
    /// Returns one signed message per sighash, in the order of `sighashes`. `sighashes` must be
    /// distinct, because the response binds a signature to its message by content alone.
    ///
    /// `note` goes to the vendor audit log, which otherwise sees only digests.
    async fn raw_sign(
        &self,
        sighashes: &[[u8; 32]],
        note: &str,
    ) -> Result<Vec<dto::SignedMessage>, FireblocksError> {
        if sighashes.len() > MAX_RAW_MESSAGES {
            return Err(FireblocksError::TooManyInputs {
                count: sighashes.len(),
            });
        }
        // Lowercase-hex of each sighash; also the `content` we expect echoed back per message.
        let expected: Vec<String> = sighashes.iter().map(hex::encode).collect();
        let deadline = Instant::now() + SIGN_MAX_DURATION;
        let tx_id = self
            .find_or_create(&external_tx_digest(sighashes), &expected, note, deadline)
            .await?;
        self.await_signatures(&tx_id, &expected, deadline).await
    }

    /// Returns the id of the live request of this sighash set, and creates one if none exists.
    ///
    /// This creates first and looks up on any failure. It rests only on the documented duplicate
    /// rejection and the lookup of an id that exists: the docs do not give the response for an
    /// unknown id, so a failed lookup cannot tell "no request" from an outage, and the create
    /// error stands. A create that failed in transit is found by the next attempt at the latest.
    ///
    /// A request that this finds already signed goes through the same poll as any other, so one
    /// path checks the response.
    async fn find_or_create(
        &self,
        digest: &str,
        messages: &[String],
        note: &str,
        deadline: Instant,
    ) -> Result<String, FireblocksError> {
        let first = {
            let known = self
                .generations
                .lock()
                .expect("no panic holds the generation map");
            known.get(digest).copied().unwrap_or(0)
        };
        for generation in first.. {
            if Instant::now() >= deadline {
                break;
            }
            self.generations
                .lock()
                .expect("no panic holds the generation map")
                .insert(digest.to_string(), generation);
            let external_tx_id = format!("{digest}-{generation}");
            let create_error = match self
                .create_raw_tx(messages, note, Some(&external_tx_id))
                .await
            {
                Ok(created) => return Ok(created.id),
                Err(e) => e,
            };
            let subpath = format!("/transactions/external_tx_id/{external_tx_id}");
            let existing = match self
                .signed_request::<dto::TransactionDetails>(Method::GET, &subpath, None)
                .await
            {
                Ok(existing) => existing,
                Err(lookup_error) => {
                    tracing::warn!(
                        %external_tx_id,
                        error = %lookup_error,
                        "no raw-sign transaction found after a failed create"
                    );
                    return Err(create_error);
                }
            };
            let tx_id = existing.id.clone();
            match existing.progress(messages) {
                RawProgress::Refused(reason) | RawProgress::Dead(reason) => tracing::warn!(
                    %external_tx_id,
                    %tx_id,
                    %reason,
                    "raw-sign id is taken by an ended transaction; moving to the next generation"
                ),
                RawProgress::Signed(_) | RawProgress::Pending => return Ok(tx_id),
            }
        }
        Err(FireblocksError::SearchTimeout {
            digest: digest.to_string(),
        })
    }

    /// Creates a RAW transaction over `messages`. A request with no `external_tx_id` is a new
    /// request on each call.
    async fn create_raw_tx(
        &self,
        messages: &[String],
        note: &str,
        external_tx_id: Option<&str>,
    ) -> Result<dto::CreateTransactionResponse, FireblocksError> {
        let messages = messages
            .iter()
            .map(|content| dto::UnsignedRawMessage {
                content: content.clone(),
            })
            .collect();
        let request = dto::RawSignRequest {
            operation: "RAW",
            asset_id: self.config.asset_id.clone(),
            source: dto::TransferPeer {
                peer_type: "VAULT_ACCOUNT",
                id: self.config.vault_account_id.clone(),
            },
            note: note.to_string(),
            external_tx_id: external_tx_id.map(str::to_string),
            extra_parameters: dto::ExtraParameters {
                raw_message_data: dto::RawMessageData {
                    messages,
                    algorithm: "MPC_ECDSA_SECP256K1",
                },
            },
        };
        let body = serde_json::to_string(&request).map_err(|e| {
            FireblocksError::SignRequest(format!("serialize raw-sign request: {e}"))
        })?;
        self.signed_request(Method::POST, "/transactions", Some(&body))
            .await
    }

    /// Polls transaction `tx_id` until every message in `expected` has a signature. A wait that
    /// gives up cancels the transaction: the next attempt may sign other digests, and then
    /// nothing collects this result.
    async fn await_signatures(
        &self,
        tx_id: &str,
        expected: &[String],
        deadline: Instant,
    ) -> Result<Vec<dto::SignedMessage>, FireblocksError> {
        let subpath = format!("/transactions/{tx_id}");
        let give_up = loop {
            match self
                .signed_request::<dto::TransactionDetails>(Method::GET, &subpath, None)
                .await
            {
                Ok(details) => match details.progress(expected) {
                    RawProgress::Signed(signed) => return Ok(signed),
                    RawProgress::Refused(reason) | RawProgress::Dead(reason) => {
                        return Err(FireblocksError::RequestFailed {
                            tx_id: tx_id.to_string(),
                            reason,
                        })
                    }
                    RawProgress::Pending => {}
                },
                Err(e) => {
                    tracing::warn!(%tx_id, error = %e, "error polling raw-sign transaction");
                }
            }
            if Instant::now() >= deadline {
                break FireblocksError::SigningTimeout(tx_id.to_string());
            }
            tokio::time::sleep(SIGN_POLL_INTERVAL).await;
        };
        self.cancel(tx_id).await;
        Err(give_up)
    }

    /// Asks Fireblocks to cancel `tx_id`. The give-up error is what the caller needs, so a failed
    /// cancel only logs: the next attempt finds the request through its `externalTxId`.
    async fn cancel(&self, tx_id: &str) {
        let subpath = format!("/transactions/{tx_id}/cancel");
        match self
            .signed_request::<dto::CancelTransactionResponse>(Method::POST, &subpath, None)
            .await
        {
            Ok(response) if response.success => {
                tracing::info!(%tx_id, "cancelled raw-sign transaction");
            }
            Ok(_) => tracing::warn!(%tx_id, "Fireblocks declined to cancel raw-sign transaction"),
            Err(e) => {
                tracing::warn!(%tx_id, error = %e, "failed to cancel raw-sign transaction");
            }
        }
    }

    /// The check of a vault with no registered descriptor. Nothing has proved the configured key
    /// yet, and a pass would persist the descriptor unchecked, so an API outage fails this check;
    /// the registered-vault check is the one that passes on an outage.
    async fn verify_new_vault(&self) -> Result<(), StartupCheckError> {
        self.verify_vault_key().await?;
        self.verify_signing()
            .await
            .map_err(StartupCheckError::Signing)
    }

    /// The check of a vault with a registered descriptor.
    async fn verify_registered_vault(&self) -> Result<(), StartupCheckError> {
        match self.verify_vault_key().await {
            Err(StartupCheckError::KeyLookup(e)) if e.is_outage() => {
                tracing::warn!(error = %e, "could not read the vault key at startup");
                Ok(())
            }
            result => result,
        }
    }

    /// Compares the public key of the vault address with [`FireblocksConfig::vault_pubkey`]. The
    /// path names change 0 and index 0: the default address, which is the address that a RAW
    /// message with no derivation path signs for.
    async fn verify_vault_key(&self) -> Result<(), StartupCheckError> {
        let subpath = format!(
            "/vault/accounts/{}/{}/0/0/public_key_info?compressed=true",
            self.config.vault_account_id, self.config.asset_id,
        );
        let info: dto::PublicKeyInformation = self
            .signed_request(Method::GET, &subpath, None)
            .await
            .map_err(StartupCheckError::KeyLookup)?;
        let reported = PublicKey::from_str(&info.public_key).map_err(|e| {
            StartupCheckError::KeyLookup(FireblocksError::Decode(format!(
                "vault public key {}: {e}",
                info.public_key
            )))
        })?;
        if reported != self.config.vault_pubkey {
            return Err(StartupCheckError::VaultKeyMismatch { reported });
        }
        Ok(())
    }

    /// RAW-signs the self-test digest and verifies the signature and the signing key against the
    /// vault script.
    async fn verify_signing(&self) -> Result<(), FireblocksError> {
        // This request has no `externalTxId`: a reused id would return the signature of an earlier
        // start, which proves nothing about the signer of this start.
        let digest: [u8; 32] = Sha256::digest(SELF_TEST_TAG).into();
        let expected = [hex::encode(digest)];
        let created = self.create_raw_tx(&expected, "self-test", None).await?;
        let signed = self
            .await_signatures(&created.id, &expected, Instant::now() + SIGN_MAX_DURATION)
            .await?;
        for message in signed {
            sign::assemble_p2wpkh_witness(
                &message.signature.full_sig,
                &message.public_key,
                &self.script_pubkey,
                &digest,
            )?;
        }
        Ok(())
    }
}

/// The hash part of the `externalTxId` of a sighash set. The order of the inputs does not change
/// it. A sighash commits to the script of its input, so the set names one vault key too.
fn external_tx_digest(sighashes: &[[u8; 32]]) -> String {
    let mut sorted = sighashes.to_vec();
    sorted.sort_unstable();
    let mut hasher = Sha256::new();
    for sighash in &sorted {
        hasher.update(sighash);
    }
    hex::encode(hasher.finalize())
}

/// Where a RAW transaction stands.
enum RawProgress {
    /// Every expected message has a signature. They are in the order of the expected messages.
    Signed(Vec<dto::SignedMessage>),
    /// The transaction can still produce the signatures.
    Pending,
    /// Fireblocks or its policy turned the request down. It holds the reason.
    Refused(String),
    /// The transaction ended, and it can never produce the signatures. It holds the reason.
    Dead(String),
}

impl dto::TransactionDetails {
    /// Reads this transaction against the messages it must sign.
    fn progress(self, expected: &[String]) -> RawProgress {
        let reason = match &self.sub_status {
            Some(sub_status) => format!("{} ({sub_status})", self.status),
            None => self.status.clone(),
        };
        // A failure status outranks any signature in the same response: the status is the
        // vendor's statement on the request, and the cost of the rule is one more MPC run.
        match self.status.as_str() {
            "REJECTED" | "BLOCKED" => return RawProgress::Refused(reason),
            "FAILED" | "CANCELLED" | "CANCELLING" | "TIMEOUT" => return RawProgress::Dead(reason),
            _ => {}
        }
        // Any other status, an unknown one too, is pending until the deadline of the poll.
        // Index the returned signatures by their echoed `content` so that each one binds to the
        // input that requested it, not to a position in the response. The case of the echoed hex
        // is the vendor's choice, and only its value matters.
        let mut by_content: HashMap<String, dto::SignedMessage> = self
            .signed_messages
            .into_iter()
            .map(|m| (m.content.to_lowercase(), m))
            .collect();
        // Only done once *every* requested sighash has a matching signature, which guards against
        // partial / incremental population mid-signing.
        let signed: Option<Vec<dto::SignedMessage>> = expected
            .iter()
            .map(|content| by_content.remove(content))
            .collect();
        match signed {
            Some(signed) => RawProgress::Signed(signed),
            None if self.status == "COMPLETED" => {
                RawProgress::Dead(format!("{reason} with missing signatures"))
            }
            None => RawProgress::Pending,
        }
    }
}

impl FireblocksSigner {
    /// Signs the inputs that spend the vault script. An input that spends any other script
    /// returns `None`: a Fireblocks operator still holds payouts at the general key, and the
    /// caller signs those through secret-service.
    ///
    /// See [`GeneralSigner::sign_owned_inputs`](crate::general::GeneralSigner::sign_owned_inputs)
    /// for the contract of the arguments.
    pub(crate) async fn sign_owned_inputs(
        &self,
        tx: &Transaction,
        input_indices: &[usize],
        prevouts: &[TxOut],
    ) -> Result<Vec<Option<Witness>>, FireblocksError> {
        // A missing prevout must not read as an input off the vault script: the caller would send
        // a vault input to secret-service, which holds no key for it.
        if prevouts.len() != tx.input.len() || input_indices.iter().any(|&i| i >= prevouts.len()) {
            return Err(FireblocksError::SignRequest(format!(
                "{} prevouts for {} inputs, signing indices {input_indices:?}",
                prevouts.len(),
                tx.input.len(),
            )));
        }
        // A repeated index gives a repeated sighash. Two inputs of one transaction never share a
        // sighash, because each commits to its own outpoint.
        let distinct: HashSet<usize> = input_indices.iter().copied().collect();
        if distinct.len() != input_indices.len() {
            return Err(FireblocksError::SignRequest(format!(
                "repeated signing index in {input_indices:?}"
            )));
        }
        // Positions in `input_indices` of the inputs that spend the vault script.
        let owned: Vec<usize> = (0..input_indices.len())
            .filter(|&slot| prevouts[input_indices[slot]].script_pubkey == self.script_pubkey)
            .collect();
        let mut witnesses = vec![None; input_indices.len()];
        if owned.is_empty() {
            return Ok(witnesses);
        }
        let sighashes = owned
            .iter()
            .map(|&slot| {
                let i = input_indices[slot];
                sign::p2wpkh_sighash(tx, i, &prevouts[i])
            })
            .collect::<Result<Vec<_>, _>>()?;
        let signed = self
            .raw_sign(&sighashes, &tx.compute_txid().to_string())
            .await?;

        for ((message, sighash), &slot) in signed.iter().zip(&sighashes).zip(&owned) {
            // Verifies that the returned pubkey controls this prevout (assemble_p2wpkh_witness
            // checks hash160 == witness program) and that the signature covers this sighash.
            let witness = sign::assemble_p2wpkh_witness(
                &message.signature.full_sig,
                &message.public_key,
                &prevouts[input_indices[slot]].script_pubkey,
                sighash,
            )?;
            witnesses[slot] = Some(witness);
        }
        Ok(witnesses)
    }
}

/// A signer and the store that [`Self::check`] ran against. It says that the check for this store
/// ran and found no fault. On a store with a descriptor and during an API
/// outage, that check compared nothing.
#[derive(Debug)]
pub struct CheckedVault<P> {
    signer: FireblocksSigner,
    store: P,
}

impl<P: WalletStore> CheckedVault<P> {
    /// Checks the configuration of `signer` against the vault, and returns the value that
    /// [`GeneralCustody::Fireblocks`](crate::GeneralCustody::Fireblocks) requires.
    ///
    /// A `store` with no descriptor gets the full check. The public key of the vault address must
    /// equal [`FireblocksConfig::vault_pubkey`]. Then a RAW request must sign a fixed digest, and
    /// the signature and the signing key must verify against the vault script. Any failure is an
    /// error, an API outage too: a pass would persist a descriptor that nothing has checked. A RAW
    /// request that waits for a human fails it.
    ///
    /// A `store` that holds a descriptor gets only the key comparison, because a RAW request is a
    /// transaction under the workspace policy. A mismatch or a rejected lookup is an error. An API
    /// outage logs a warning and passes, so that a vendor outage does not stop a restart. A wrong
    /// host and a TLS failure read as an outage, and the first signature reports them.
    ///
    /// The key lookup needs a role that the vendor documentation lists as Admin or Non-Signing
    /// Admin; no live tenant has confirmed this yet.
    pub async fn check(signer: FireblocksSigner, mut store: P) -> Result<Self, StartupCheckError> {
        let persisted = P::initialize(&mut store)
            .await
            .map_err(|e| StartupCheckError::Store(Box::new(e)))?;
        if persisted.descriptor.is_some() {
            signer.verify_registered_vault().await?;
        } else {
            signer.verify_new_vault().await?;
        }
        Ok(Self { signer, store })
    }
}

impl<P> CheckedVault<P> {
    /// Splits the value into the watch-only descriptor of the vault script, the signer, and the
    /// store.
    pub(super) fn into_parts(self) -> (ExtendedDescriptor, FireblocksSigner, P) {
        let vault_key = bdk_wallet::bitcoin::PublicKey::new(self.signer.config.vault_pubkey);
        let (descriptor, ..) = descriptor!(wpkh(vault_key)).expect("valid wpkh() descriptor");
        (descriptor, self.signer, self.store)
    }
}

#[cfg(feature = "test-utils")]
impl<P> CheckedVault<P> {
    /// Skips the check, for a test with no vault API.
    pub const fn unchecked(signer: FireblocksSigner, store: P) -> Self {
        Self { signer, store }
    }
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::{
        absolute::LockTime,
        hashes::Hash,
        secp256k1::{Message, Secp256k1, SecretKey},
        transaction::Version,
        Amount, OutPoint, Sequence, TxIn,
    };
    use serde_json::json;
    use wiremock::{
        matchers::{body_partial_json, method, path, query_param},
        Mock, MockServer, Request, ResponseTemplate,
    };

    use super::*;
    use crate::test_utils::{MemoryStore, TEST_RSA_PRIVATE_PEM};

    const VAULT_SECRET: [u8; 32] = [7; 32];
    const TX_ID: &str = "tx-1";

    fn vault_pubkey() -> PublicKey {
        let secret = SecretKey::from_slice(&VAULT_SECRET).expect("valid scalar");
        secret.public_key(&Secp256k1::new())
    }

    fn config(base_url: &str) -> FireblocksConfig {
        FireblocksConfig {
            base_url: base_url.to_string(),
            api_key: "key".to_string(),
            vault_account_id: "0".to_string(),
            asset_id: "BTC_TEST".to_string(),
            vault_pubkey: vault_pubkey(),
        }
    }

    /// A signer whose API host refuses the connection at once, so a call that reaches the network
    /// fails without a resolver round trip.
    fn offline_signer() -> FireblocksSigner {
        FireblocksSigner::build(
            config("http://127.0.0.1:9/"),
            TEST_RSA_PRIVATE_PEM.as_bytes(),
        )
        .expect("valid config")
    }

    /// A signer on a mock server, which speaks plain HTTP.
    fn mock_signer(server: &MockServer) -> FireblocksSigner {
        FireblocksSigner::build(config(&server.uri()), TEST_RSA_PRIVATE_PEM.as_bytes())
            .expect("valid config")
    }

    const SIGHASH: [u8; 32] = [0x11; 32];

    /// The `externalTxId` of `[SIGHASH]` at `generation`.
    fn external_id(generation: u64) -> String {
        format!("{}-{generation}", external_tx_digest(&[SIGHASH]))
    }

    /// Finds or creates the request of `[SIGHASH]`, within `limit`.
    async fn find_in(
        signer: &FireblocksSigner,
        limit: Duration,
    ) -> Result<String, FireblocksError> {
        signer
            .find_or_create(
                &external_tx_digest(&[SIGHASH]),
                &[hex::encode(SIGHASH)],
                "note",
                Instant::now() + limit,
            )
            .await
    }

    /// What `raw_sign` does for `[SIGHASH]`.
    async fn sign_sighash(
        signer: &FireblocksSigner,
    ) -> Result<Vec<dto::SignedMessage>, FireblocksError> {
        let tx_id = find_in(signer, SIGN_MAX_DURATION).await?;
        signer
            .await_signatures(
                &tx_id,
                &[hex::encode(SIGHASH)],
                Instant::now() + SIGN_MAX_DURATION,
            )
            .await
    }

    fn lookup_path(generation: u64) -> String {
        format!(
            "/v1/transactions/external_tx_id/{}",
            external_id(generation)
        )
    }

    /// A transaction detail body with signatures over `signed`, from `secret`.
    fn details(status: &str, signed: &[[u8; 32]], secret: &[u8; 32]) -> serde_json::Value {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(secret).expect("valid scalar");
        let messages: Vec<_> = signed
            .iter()
            .map(|digest| {
                let signature = secp.sign_ecdsa(&Message::from_digest(*digest), &secret);
                json!({
                    "content": hex::encode(digest),
                    "publicKey": hex::encode(secret.public_key(&secp).serialize()),
                    "signature": { "fullSig": hex::encode(signature.serialize_compact()) },
                })
            })
            .collect();
        json!({ "id": TX_ID, "status": status, "signedMessages": messages })
    }

    /// Mounts a mock that answers `method_name path_str` with `response`, `times` times in total.
    async fn expect(
        server: &MockServer,
        method_name: &str,
        path_str: &str,
        response: ResponseTemplate,
        times: u64,
    ) {
        Mock::given(method(method_name))
            .and(path(path_str))
            .respond_with(response)
            .expect(times)
            .mount(server)
            .await;
    }

    fn ok(body: serde_json::Value) -> ResponseTemplate {
        ResponseTemplate::new(200).set_body_json(body)
    }

    fn created() -> ResponseTemplate {
        ok(json!({ "id": TX_ID }))
    }

    /// The HTTP 400 that Fireblocks returns for a repeated `externalTxId`.
    fn rejected() -> ResponseTemplate {
        ResponseTemplate::new(400).set_body_json(json!({ "message": "duplicate", "code": 1 }))
    }

    const CANCEL_PATH: &str = "/v1/transactions/tx-1/cancel";
    const TX_PATH: &str = "/v1/transactions/tx-1";
    const CREATE_PATH: &str = "/v1/transactions";
    const SHORT: Duration = Duration::from_millis(50);

    #[test]
    fn a_request_id_does_not_depend_on_input_order() {
        let (a, b) = ([1; 32], [2; 32]);
        assert_eq!(external_tx_digest(&[a, b]), external_tx_digest(&[b, a]));
        assert_ne!(external_tx_digest(&[a]), external_tx_digest(&[a, b]));
    }

    #[tokio::test]
    async fn a_signing_request_carries_its_external_id() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(CREATE_PATH))
            .and(body_partial_json(json!({
                "operation": "RAW",
                "assetId": "BTC_TEST",
                "source": { "type": "VAULT_ACCOUNT", "id": "0" },
                "externalTxId": external_id(0),
                "note": "note",
                "extraParameters": {
                    "rawMessageData": {
                        "algorithm": "MPC_ECDSA_SECP256K1",
                        "messages": [{ "content": hex::encode(SIGHASH) }],
                    },
                },
            })))
            .respond_with(created())
            .expect(1)
            .mount(&server)
            .await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[SIGHASH], &VAULT_SECRET)),
            1,
        )
        .await;

        let signed = sign_sighash(&mock_signer(&server)).await.expect("signed");
        assert_eq!(signed.len(), 1);
        assert_eq!(signed[0].content, hex::encode(SIGHASH));
    }

    /// A retry of an unchanged transaction joins the first request, so it starts no second MPC
    /// run and still collects the signature.
    #[tokio::test]
    async fn a_duplicate_rejection_resumes_the_existing_request() {
        let server = MockServer::start().await;
        expect(&server, "POST", CREATE_PATH, rejected(), 1).await;
        expect(
            &server,
            "GET",
            &lookup_path(0),
            ok(details("PENDING_SIGNATURE", &[], &VAULT_SECRET)),
            1,
        )
        .await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[SIGHASH], &VAULT_SECRET)),
            1,
        )
        .await;

        sign_sighash(&mock_signer(&server))
            .await
            .expect("signed through the existing request");
    }

    /// An id stays taken after its request ends, and the same sighashes must still be signable.
    #[tokio::test]
    async fn a_dead_request_moves_the_id_to_the_next_generation() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(CREATE_PATH))
            .and(body_partial_json(json!({ "externalTxId": external_id(0) })))
            .respond_with(rejected())
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path(CREATE_PATH))
            .and(body_partial_json(json!({ "externalTxId": external_id(1) })))
            .respond_with(created())
            .expect(1)
            .mount(&server)
            .await;
        expect(
            &server,
            "GET",
            &lookup_path(0),
            ok(details("CANCELLED", &[], &VAULT_SECRET)),
            1,
        )
        .await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[SIGHASH], &VAULT_SECRET)),
            1,
        )
        .await;

        sign_sighash(&mock_signer(&server))
            .await
            .expect("signed under the next generation");
    }

    /// A refused request ended, so the same sighashes move to the next generation, and a corrected
    /// policy applies there.
    #[tokio::test]
    async fn a_refused_request_moves_the_id_to_the_next_generation() {
        for status in ["REJECTED", "BLOCKED"] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path(CREATE_PATH))
                .and(body_partial_json(json!({ "externalTxId": external_id(0) })))
                .respond_with(rejected())
                .expect(1)
                .mount(&server)
                .await;
            Mock::given(method("POST"))
                .and(path(CREATE_PATH))
                .and(body_partial_json(json!({ "externalTxId": external_id(1) })))
                .respond_with(created())
                .expect(1)
                .mount(&server)
                .await;
            expect(
                &server,
                "GET",
                &lookup_path(0),
                ok(details(status, &[], &VAULT_SECRET)),
                1,
            )
            .await;
            expect(
                &server,
                "GET",
                TX_PATH,
                ok(details("COMPLETED", &[SIGHASH], &VAULT_SECRET)),
                1,
            )
            .await;

            sign_sighash(&mock_signer(&server))
                .await
                .unwrap_or_else(|e| panic!("{status}: signed under the next generation: {e:?}"));
        }
    }

    /// A broken server must not hold the signer in the walk.
    #[tokio::test]
    async fn a_walk_through_dead_requests_stops_at_its_deadline() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path(CREATE_PATH))
            .respond_with(rejected())
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .respond_with(ok(details("FAILED", &[], &VAULT_SECRET)))
            .mount(&server)
            .await;

        let err = find_in(&mock_signer(&server), SHORT)
            .await
            .expect_err("every generation is dead");
        assert!(
            matches!(err, FireblocksError::SearchTimeout { .. }),
            "got {err:?}"
        );
    }

    /// A request that completed without the signatures can never produce them.
    #[tokio::test]
    async fn a_completed_request_without_signatures_is_a_dead_request() {
        let server = MockServer::start().await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[], &VAULT_SECRET)),
            1,
        )
        .await;
        expect(&server, "POST", CANCEL_PATH, created(), 0).await;
        let err = mock_signer(&server)
            .await_signatures(
                TX_ID,
                &[hex::encode(SIGHASH)],
                Instant::now() + SIGN_MAX_DURATION,
            )
            .await
            .expect_err("no signature can arrive");
        assert!(
            matches!(err, FireblocksError::RequestFailed { .. }),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_create_with_no_request_behind_it_returns_the_create_error() {
        let server = MockServer::start().await;
        expect(&server, "POST", CREATE_PATH, rejected(), 1).await;
        expect(
            &server,
            "GET",
            &lookup_path(0),
            ResponseTemplate::new(404),
            1,
        )
        .await;

        let err = sign_sighash(&mock_signer(&server))
            .await
            .expect_err("the create failed");
        assert!(err.to_string().contains("duplicate"), "got {err}");
    }

    /// Polls the transaction of [`TX_ID`] for `[SIGHASH]` until [`SHORT`] runs out.
    async fn wait_briefly(server: &MockServer) -> FireblocksError {
        mock_signer(server)
            .await_signatures(TX_ID, &[hex::encode(SIGHASH)], Instant::now() + SHORT)
            .await
            .expect_err("nothing signs")
    }

    #[tokio::test]
    async fn a_wait_that_times_out_cancels_the_request() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(TX_PATH))
            .respond_with(ok(details("PENDING_AUTHORIZATION", &[], &VAULT_SECRET)))
            .mount(&server)
            .await;
        expect(
            &server,
            "POST",
            CANCEL_PATH,
            ok(json!({ "success": true })),
            1,
        )
        .await;

        let err = wait_briefly(&server).await;
        assert!(
            matches!(err, FireblocksError::SigningTimeout(ref id) if id == TX_ID),
            "got {err:?}"
        );
    }

    /// A blip must not drop a request that can still sign.
    #[tokio::test]
    async fn a_poll_survives_errors_and_reads_the_signatures() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(TX_PATH))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(8)
            .with_priority(1)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(TX_PATH))
            .respond_with(ok(details("COMPLETED", &[SIGHASH], &VAULT_SECRET)))
            .mount(&server)
            .await;
        expect(&server, "POST", CANCEL_PATH, created(), 0).await;

        mock_signer(&server)
            .await_signatures(
                TX_ID,
                &[hex::encode(SIGHASH)],
                Instant::now() + SIGN_MAX_DURATION,
            )
            .await
            .expect("the poll recovers");
    }

    /// A walk that uses the whole limit must not lose a request that is already signed.
    #[tokio::test]
    async fn a_wait_past_its_deadline_still_polls_once() {
        let server = MockServer::start().await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[SIGHASH], &VAULT_SECRET)),
            1,
        )
        .await;
        expect(&server, "POST", CANCEL_PATH, created(), 0).await;

        mock_signer(&server)
            .await_signatures(TX_ID, &[hex::encode(SIGHASH)], Instant::now())
            .await
            .expect("the signatures are there");
    }

    /// Public half of [`TEST_RSA_PRIVATE_PEM`].
    const TEST_RSA_PUBLIC_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAjDX7ptIqTH1iEnqMABIs
duiWmHYCzc5/8UFDATZkSRXuBcd9PA7v/FCXKq5dS9nWqlN6AL7WcZe4yEvalxxm
wmxjcgMqS/wUevcSlWSYvBRh+qycjfnSNcVvwm5zqPcPemaLcTON1xqHxdMznd6Q
HyAqx+YZgr8fm0R+8zmCQCr3uhvJWRkuhee7KYL9hM/t2NK105EyaBMOO1+pHbKL
kWcw9isTM82RrQMRtpiM46M0AqJG/EQcaUHsrUMIOE55ubiyK/yKyjrPal12h8oj
vob494gc0G2+Lz3SDoe9fb5gJZmTrJA0SnvWNpVSapS2SaIU4q0X9nkW9ZZCRPj3
UwIDAQAB
-----END PUBLIC KEY-----
"#;

    /// Fireblocks rejects a request unless the JWT claims match what the server received, and
    /// the key lookup is the one request with a query string. The test also pins the `jsonwebtoken`
    /// crypto provider: with no provider feature compiled in, the signer factory of the default
    /// provider panics on the first `encode` call.
    #[tokio::test]
    async fn the_jwt_of_each_request_matches_what_was_sent() {
        let server = MockServer::start().await;
        serve_vault(&server, &VAULT_SECRET).await;

        mock_signer(&server)
            .verify_new_vault()
            .await
            .expect("passes");

        let requests = server.received_requests().await.expect("recording is on");
        assert_eq!(requests.len(), 3, "lookup, create and poll");
        let key = jsonwebtoken::DecodingKey::from_rsa_pem(TEST_RSA_PUBLIC_PEM.as_bytes())
            .expect("valid public key");
        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        for request in &requests {
            let bearer = request.headers["authorization"]
                .to_str()
                .expect("ascii header");
            let token = bearer.strip_prefix("Bearer ").expect("a bearer token");
            let claims = jsonwebtoken::decode::<serde_json::Value>(token, &key, &validation)
                .expect("a token from the operator key")
                .claims;

            let sent_uri = match request.url.query() {
                Some(query) => format!("{}?{query}", request.url.path()),
                None => request.url.path().to_string(),
            };
            assert_eq!(claims["uri"], sent_uri);
            assert_eq!(
                claims["bodyHash"],
                hex::encode(Sha256::digest(&request.body))
            );
            assert_eq!(
                claims["sub"],
                request.headers["x-api-key"].to_str().expect("ascii header")
            );
        }
    }

    /// The caller needs the reason for the give-up, not the reason that the cancel failed.
    #[tokio::test]
    async fn a_failed_cancel_keeps_the_give_up_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(TX_PATH))
            .respond_with(ok(details("PENDING_SIGNATURE", &[], &VAULT_SECRET)))
            .mount(&server)
            .await;
        expect(&server, "POST", CANCEL_PATH, ResponseTemplate::new(500), 1).await;

        let err = wait_briefly(&server).await;
        assert!(
            matches!(err, FireblocksError::SigningTimeout(_)),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_failed_request_reports_its_sub_status_and_is_not_cancelled() {
        let server = MockServer::start().await;
        expect(&server, "POST", CREATE_PATH, created(), 1).await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(json!({
                "id": TX_ID,
                "status": "BLOCKED",
                "subStatus": "BLOCKED_BY_POLICY",
            })),
            1,
        )
        .await;
        expect(&server, "POST", CANCEL_PATH, created(), 0).await;

        let err = sign_sighash(&mock_signer(&server))
            .await
            .expect_err("policy blocks it");
        assert!(
            err.to_string().contains("BLOCKED (BLOCKED_BY_POLICY)"),
            "got {err}"
        );
    }

    #[tokio::test]
    async fn a_request_of_more_than_the_message_limit_never_reaches_the_api() {
        let server = MockServer::start().await;
        expect(&server, "POST", CREATE_PATH, created(), 0).await;
        let sighashes: Vec<[u8; 32]> = (0..=MAX_RAW_MESSAGES).map(distinct_digest).collect();

        let err = mock_signer(&server)
            .raw_sign(&sighashes, "note")
            .await
            .expect_err("over the limit");
        assert!(
            matches!(err, FireblocksError::TooManyInputs { count } if count == MAX_RAW_MESSAGES + 1),
            "got {err:?}"
        );
    }

    #[tokio::test]
    async fn a_request_at_the_message_limit_is_signed() {
        let server = MockServer::start().await;
        let sighashes: Vec<[u8; 32]> = (0..MAX_RAW_MESSAGES).map(distinct_digest).collect();
        expect(&server, "POST", CREATE_PATH, created(), 1).await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &sighashes, &VAULT_SECRET)),
            1,
        )
        .await;

        let signed = mock_signer(&server)
            .raw_sign(&sighashes, "note")
            .await
            .expect("at the limit");
        assert_eq!(signed.len(), MAX_RAW_MESSAGES);
    }

    fn distinct_digest(i: usize) -> [u8; 32] {
        Sha256::digest(i.to_be_bytes()).into()
    }

    #[test]
    fn a_base_url_must_be_a_bare_https_origin() {
        for url in [
            "http://api.fireblocks.io",
            "ftp://x.io",
            "api.fireblocks.io",
            "https://api.fireblocks.io/v1",
            "https://api.fireblocks.io?a=b",
            "https://api.fireblocks.io#a",
            "https://user:pass@api.fireblocks.io",
        ] {
            let err = FireblocksSigner::new(config(url), TEST_RSA_PRIVATE_PEM.as_bytes())
                .expect_err("not a bare https origin");
            assert!(
                matches!(err, FireblocksInitError::InvalidBaseUrl),
                "{url}: got {err:?}"
            );
        }
    }

    /// A host that does not answer reads as an outage, which a registered vault survives.
    #[tokio::test]
    async fn an_unreachable_host_passes_the_check_of_a_registered_vault() {
        offline_signer()
            .verify_registered_vault()
            .await
            .expect("an outage does not stop a restart");
    }

    /// A stray slash in the path would make Fireblocks reject the JWT `uri` claim.
    #[test]
    fn a_trailing_slash_leaves_the_base_url_bare() {
        let base = parse_base_url("https://api.fireblocks.io/").expect("valid");
        assert_eq!(base, "https://api.fireblocks.io");
    }

    /// A redirect target would receive the API key and the JWT.
    #[tokio::test]
    async fn a_redirect_is_an_error_and_is_not_followed() {
        let server = MockServer::start().await;
        expect(
            &server,
            "POST",
            CREATE_PATH,
            ResponseTemplate::new(307).insert_header("Location", "/elsewhere"),
            1,
        )
        .await;
        expect(
            &server,
            "GET",
            &lookup_path(0),
            ResponseTemplate::new(302).insert_header("Location", "/elsewhere"),
            1,
        )
        .await;
        Mock::given(path("/elsewhere"))
            .respond_with(created())
            .expect(0)
            .mount(&server)
            .await;

        let err = sign_sighash(&mock_signer(&server))
            .await
            .expect_err("a redirect ends the request");
        assert!(matches!(err, FireblocksError::Api { .. }), "got {err:?}");
    }

    fn self_test_digest() -> [u8; 32] {
        Sha256::digest(SELF_TEST_TAG).into()
    }

    /// Answers the public key lookup of the vault address with `key`.
    async fn report_public_key(server: &MockServer, key: &str) {
        Mock::given(method("GET"))
            .and(path(KEY_PATH))
            .and(query_param("compressed", "true"))
            .respond_with(ok(json!({ "publicKey": key })))
            .expect(1)
            .mount(server)
            .await;
    }

    const KEY_PATH: &str = "/v1/vault/accounts/0/BTC_TEST/0/0/public_key_info";

    fn other_pubkey() -> String {
        SecretKey::from_slice(&[8; 32])
            .expect("valid scalar")
            .public_key(&Secp256k1::new())
            .to_string()
    }

    /// Mounts a vault whose key matches and that signs the self-test digest with `secret`.
    async fn serve_vault(server: &MockServer, secret: &[u8; 32]) {
        report_public_key(server, &vault_pubkey().to_string()).await;
        expect(server, "POST", CREATE_PATH, created(), 1).await;
        expect(
            server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[self_test_digest()], secret)),
            1,
        )
        .await;
    }

    /// A store that holds the descriptor of the vault.
    async fn registered_store() -> MemoryStore {
        let key = bdk_wallet::bitcoin::PublicKey::new(vault_pubkey());
        let (descriptor, ..) = descriptor!(wpkh(key)).expect("valid wpkh() descriptor");
        let mut store = MemoryStore::new();
        bdk_wallet::Wallet::create_single(descriptor)
            .network(bdk_wallet::bitcoin::Network::Regtest)
            .create_wallet_async(&mut store)
            .await
            .expect("a wallet in memory");
        store
    }

    #[tokio::test]
    async fn an_empty_store_gets_the_key_compare_and_the_test_signature() {
        let server = MockServer::start().await;
        serve_vault(&server, &VAULT_SECRET).await;

        CheckedVault::check(mock_signer(&server), MemoryStore::new())
            .await
            .expect("passes");
    }

    /// A RAW request is a transaction under the workspace policy, so a restart sends none.
    #[tokio::test]
    async fn a_store_with_a_descriptor_gets_only_the_key_compare() {
        let server = MockServer::start().await;
        report_public_key(&server, &vault_pubkey().to_string()).await;
        expect(&server, "POST", CREATE_PATH, created(), 0).await;

        CheckedVault::check(mock_signer(&server), registered_store().await)
            .await
            .expect("passes");
    }

    /// A reused request would answer with the signature of an earlier start, which says nothing
    /// about the signer of this start.
    #[tokio::test]
    async fn the_test_signature_comes_from_a_fresh_request() {
        let server = MockServer::start().await;
        serve_vault(&server, &VAULT_SECRET).await;

        mock_signer(&server)
            .verify_new_vault()
            .await
            .expect("passes");

        let requests = server.received_requests().await.expect("recording is on");
        let create: &Request = requests
            .iter()
            .find(|r| r.method.as_str() == "POST")
            .expect("a RAW request");
        let body: serde_json::Value = create.body_json().expect("json body");
        assert!(body.get("externalTxId").is_none(), "got {body}");
    }

    #[tokio::test]
    async fn a_vault_key_that_differs_is_an_error_and_signs_nothing() {
        for new_vault in [true, false] {
            let server = MockServer::start().await;
            report_public_key(&server, &other_pubkey()).await;
            expect(&server, "POST", CREATE_PATH, created(), 0).await;
            let signer = mock_signer(&server);

            let result = if new_vault {
                signer.verify_new_vault().await
            } else {
                signer.verify_registered_vault().await
            };
            let err = result.expect_err("wrong key");
            assert!(
                matches!(err, StartupCheckError::VaultKeyMismatch { .. }),
                "new vault {new_vault}: got {err:?}"
            );
        }
    }

    /// An unreadable answer says nothing about the configured key, and it is no outage either.
    #[tokio::test]
    async fn an_unreadable_vault_key_is_an_error_and_not_a_mismatch() {
        for new_vault in [true, false] {
            let server = MockServer::start().await;
            report_public_key(&server, "1044c364").await;
            let signer = mock_signer(&server);

            let result = if new_vault {
                signer.verify_new_vault().await
            } else {
                signer.verify_registered_vault().await
            };
            let err = result.expect_err("no key to compare");
            assert!(
                matches!(
                    err,
                    StartupCheckError::KeyLookup(FireblocksError::Decode(_))
                ),
                "new vault {new_vault}: got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_signature_from_another_key_fails_a_new_vault() {
        let server = MockServer::start().await;
        serve_vault(&server, &[8; 32]).await;

        let err = mock_signer(&server)
            .verify_new_vault()
            .await
            .expect_err("wrong signing key");
        assert!(
            matches!(err, StartupCheckError::Signing(FireblocksError::Witness(_))),
            "got {err:?}"
        );
    }

    /// Nothing has proved the key of a new vault, so its descriptor must wait for the API.
    #[tokio::test]
    async fn an_api_outage_fails_a_new_vault() {
        let server = MockServer::start().await;
        expect(&server, "GET", KEY_PATH, ResponseTemplate::new(503), 1).await;

        let err = mock_signer(&server)
            .verify_new_vault()
            .await
            .expect_err("no key to compare");
        assert!(
            matches!(
                err,
                StartupCheckError::KeyLookup(FireblocksError::Api { status: 503, .. })
            ),
            "got {err:?}"
        );
    }

    /// The store pins a descriptor that passed the check, and the outage stops no duty that needs
    /// no signature.
    #[tokio::test]
    async fn an_api_outage_does_not_stop_a_registered_vault() {
        for status in [429, 500, 503] {
            let server = MockServer::start().await;
            expect(&server, "GET", KEY_PATH, ResponseTemplate::new(status), 1).await;

            mock_signer(&server)
                .verify_registered_vault()
                .await
                .expect("an outage passes");
        }
    }

    /// A revoked key or an edited `vault_account_id` exists at startup, so it must not wait for
    /// the first duty.
    #[tokio::test]
    async fn a_rejected_lookup_stops_a_registered_vault() {
        for status in [401, 403, 404] {
            let server = MockServer::start().await;
            expect(&server, "GET", KEY_PATH, ResponseTemplate::new(status), 1).await;

            let err = mock_signer(&server)
                .verify_registered_vault()
                .await
                .expect_err("not an outage");
            assert!(
                matches!(err, StartupCheckError::KeyLookup(_)),
                "{status}: got {err:?}"
            );
        }
    }

    #[test]
    fn debug_output_redacts_the_api_key() {
        let mut config = config("https://fireblocks.invalid");
        config.api_key = "sentinel-key".to_string();
        let signer =
            FireblocksSigner::new(config, TEST_RSA_PRIVATE_PEM.as_bytes()).expect("valid config");
        for rendered in [format!("{signer:?}"), format!("{signer:#?}")] {
            assert!(!rendered.contains("sentinel-key"), "leaked: {rendered}");
        }
    }

    /// A Fireblocks operator keeps payouts at the general key, and only secret-service can sign
    /// those. The signer leaves them to the caller and does not ask the vault.
    #[tokio::test]
    async fn an_input_off_the_vault_script_is_left_for_the_caller() {
        let tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..TxIn::default()
            }],
            output: Vec::new(),
        };
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_op_return([]),
        };
        let witnesses = offline_signer()
            .sign_owned_inputs(&tx, &[0], &[prevout])
            .await
            .expect("no vault input, so no API call");
        assert_eq!(witnesses, vec![None]);
    }

    #[tokio::test]
    async fn a_signing_index_past_the_inputs_is_an_error() {
        let tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: Vec::new(),
        };
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_op_return([]),
        };
        let err = offline_signer()
            .sign_owned_inputs(&tx, &[1], &[prevout])
            .await
            .expect_err("input 1 does not exist");
        assert!(
            matches!(err, FireblocksError::SignRequest(_)),
            "got {err:?}"
        );
    }

    /// One signature must not fill two entries of the result.
    #[tokio::test]
    async fn a_repeated_signing_index_is_an_error() {
        let signer = offline_signer();
        let tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: Vec::new(),
        };
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: signer.script_pubkey.clone(),
        };
        let err = signer
            .sign_owned_inputs(&tx, &[0, 0], &[prevout])
            .await
            .expect_err("index 0 appears twice");
        assert!(
            matches!(err, FireblocksError::SignRequest(_)),
            "got {err:?}"
        );
    }

    /// A `None` slot goes to secret-service, so a witness in the wrong slot means a wrong signer.
    /// The server answers in reverse order: position in the response must not bind a signature.
    #[tokio::test]
    async fn each_vault_input_gets_its_own_witness_in_a_mixed_transaction() {
        let server = MockServer::start().await;
        let signer = mock_signer(&server);
        let tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: (0..3)
                .map(|vout| TxIn {
                    previous_output: OutPoint::new(bdk_wallet::bitcoin::Txid::all_zeros(), vout),
                    ..TxIn::default()
                })
                .collect(),
            output: Vec::new(),
        };
        let vault_prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: signer.script_pubkey.clone(),
        };
        let foreign_prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_op_return([]),
        };
        let prevouts = [
            vault_prevout.clone(),
            foreign_prevout,
            vault_prevout.clone(),
        ];
        let sighash_0 = sign::p2wpkh_sighash(&tx, 0, &vault_prevout).expect("sighash");
        let sighash_2 = sign::p2wpkh_sighash(&tx, 2, &vault_prevout).expect("sighash");
        expect(&server, "POST", CREATE_PATH, created(), 1).await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[sighash_2, sighash_0], &VAULT_SECRET)),
            1,
        )
        .await;

        let witnesses = signer
            .sign_owned_inputs(&tx, &[0, 1, 2], &prevouts)
            .await
            .expect("signed");

        assert_eq!(witnesses[1], None, "secret-service signs this input");
        let secp = Secp256k1::verification_only();
        for (slot, sighash) in [(0, sighash_0), (2, sighash_2)] {
            let witness = witnesses[slot].as_ref().expect("a vault input");
            let der = witness.nth(0).expect("a signature");
            let signature =
                bdk_wallet::bitcoin::secp256k1::ecdsa::Signature::from_der(&der[..der.len() - 1])
                    .expect("DER signature");
            secp.verify_ecdsa(&Message::from_digest(sighash), &signature, &vault_pubkey())
                .expect("the witness of this slot signs this input");
        }
    }

    /// A vault input with no prevout must not go to secret-service as an input off the vault.
    #[tokio::test]
    async fn a_short_prevout_list_is_an_error() {
        let tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: Vec::new(),
        };
        let err = offline_signer()
            .sign_owned_inputs(&tx, &[0], &[])
            .await
            .expect_err("the prevout of input 0 is missing");
        assert!(
            matches!(err, FireblocksError::SignRequest(_)),
            "got {err:?}"
        );
    }

    fn parsed(body: serde_json::Value) -> dto::TransactionDetails {
        serde_json::from_value(body).expect("a detail body")
    }

    #[test]
    fn partial_signatures_keep_a_request_pending() {
        let details = parsed(details("PENDING_SIGNATURE", &[[1; 32]], &VAULT_SECRET));
        let expected = [hex::encode([1; 32]), hex::encode([2; 32])];
        assert!(matches!(details.progress(&expected), RawProgress::Pending));
    }

    #[test]
    fn signatures_come_back_in_the_order_of_the_request() {
        let details = parsed(details("COMPLETED", &[[1; 32], [2; 32]], &VAULT_SECRET));
        let expected = [hex::encode([2; 32]), hex::encode([1; 32])];
        let RawProgress::Signed(signed) = details.progress(&expected) else {
            panic!("every message is signed");
        };
        let contents: Vec<_> = signed.into_iter().map(|m| m.content).collect();
        assert_eq!(contents, expected);
    }

    #[test]
    fn a_failure_status_outranks_signatures() {
        let expected = [hex::encode([1; 32])];
        for status in ["REJECTED", "BLOCKED"] {
            let progress = parsed(details(status, &[[1; 32]], &VAULT_SECRET)).progress(&expected);
            assert!(matches!(progress, RawProgress::Refused(_)), "{status}");
        }
        for status in ["FAILED", "CANCELLED", "CANCELLING", "TIMEOUT"] {
            let progress = parsed(details(status, &[[1; 32]], &VAULT_SECRET)).progress(&expected);
            assert!(matches!(progress, RawProgress::Dead(_)), "{status}");
        }
    }

    /// The hex case of the echoed content is the vendor's choice.
    #[test]
    fn an_echoed_message_matches_in_any_hex_case() {
        let mut details = parsed(details("COMPLETED", &[[0xab; 32]], &VAULT_SECRET));
        details.signed_messages[0].content = details.signed_messages[0].content.to_uppercase();
        let expected = [hex::encode([0xab; 32])];
        assert!(matches!(
            details.progress(&expected),
            RawProgress::Signed(_)
        ));
    }

    #[test]
    fn any_other_status_keeps_a_request_pending() {
        let expected = [hex::encode([1; 32])];
        for status in ["SUBMITTED", "PENDING_SIGNATURE", "BROADCASTING", ""] {
            let progress = parsed(details(status, &[], &VAULT_SECRET)).progress(&expected);
            assert!(matches!(progress, RawProgress::Pending), "{status}");
        }
    }
}
