//! Fireblocks-backed [`GeneralWallet`](super::GeneralWallet) implementation.
//!
//! Custodies the operator's general-purpose (fee-paying / earnings) wallet in a Fireblocks
//! BTC vault account instead of a local BDK wallet. All bridge protocol keys (anchors,
//! presigned-tx keys) remain in secret-service; Fireblocks only ever contributes a funding
//! input + optional change to cover fees and to top up internal pools.
//!
//! ## Why RAW signing
//!
//! Fireblocks can produce a BTC transaction two ways. The `TRANSFER` + `inputsSelection`
//! flow has Fireblocks build *and broadcast* its own transaction — unusable here, because we
//! must inject a foreign Taproot anchor input, force v3/TRUC, control exact outputs, and get
//! the PSBT back to package with the parent. So this backend uses **`RAW` signing**: it builds
//! the unsigned bitcoin transaction itself (input selection, change, sighashes), sends the
//! sighashes to Fireblocks for ECDSA signing, and assembles the witnesses.
//!
//! Fireblocks BTC is ECDSA secp256k1, so vault addresses are **P2WPKH**; funding witnesses are
//! `[DER-sig + SIGHASH_ALL byte, compressed pubkey]`. The anchor input stays Taproot and is
//! left unsigned for secret-service (per the [`GeneralWallet`](super::GeneralWallet) signing
//! contract).
//!
//! ## Auth
//!
//! Every request carries `X-API-Key: <api key>` and `Authorization: Bearer <JWT>`, where the
//! JWT is RS256-signed with the operator's Fireblocks API secret (an RSA private key) and
//! carries `{ uri, nonce, iat, exp, sub = api key, bodyHash = SHA256(raw body) }`.

mod auth;
mod dto;

use std::{fmt, str::FromStr};

use bdk_wallet::bitcoin::{
    address::NetworkUnchecked, Address, Amount, Denomination, FeeRate, Network, OutPoint,
    ScriptBuf, Transaction, TxOut, Txid,
};
use reqwest::Method;
use serde::de::DeserializeOwned;
use thiserror::Error;

use super::{AnchorInfo, FundedPsbt, GeneralWallet, UtxoInfo};

/// Connection + identity configuration for a Fireblocks BTC vault account.
#[derive(Clone)]
pub struct FireblocksConfig {
    /// API host root, **without** the `/v1` path segment, e.g. `https://api.fireblocks.io`.
    /// Requests append `/v1/<path>` themselves so the JWT `uri` claim and the request URL
    /// stay in lockstep.
    pub base_url: String,
    /// Fireblocks API key (sent as the `X-API-Key` header).
    pub api_key: String,
    /// Vault account id holding the BTC asset.
    pub vault_account_id: String,
    /// Asset id for the network — `BTC` on mainnet, `BTC_TEST` on test networks.
    pub asset_id: String,
    /// Bitcoin network the vault operates on. Used to parse/validate the deposit address.
    pub network: Network,
    /// The vault account's BTC deposit address (P2WPKH). Operator-provided so
    /// [`FireblocksGeneralWallet::script_pubkey`](super::GeneralWallet::script_pubkey) stays
    /// synchronous and infallible.
    pub deposit_address: String,
}

impl fmt::Debug for FireblocksConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact the API key; everything else is non-secret operational config.
        f.debug_struct("FireblocksConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"<redacted>")
            .field("vault_account_id", &self.vault_account_id)
            .field("asset_id", &self.asset_id)
            .field("network", &self.network)
            .field("deposit_address", &self.deposit_address)
            .finish()
    }
}

/// Errors produced by the Fireblocks backend.
#[derive(Debug, Error)]
pub enum FireblocksError {
    /// Failed to construct the RS256 signing key from the provided API secret PEM.
    #[error("invalid Fireblocks API secret (RSA PEM): {0}")]
    SigningKey(String),
    /// The configured deposit address could not be parsed or did not match the network.
    #[error("invalid deposit address: {0}")]
    DepositAddress(String),
    /// JWT construction failed.
    #[error("jwt: {0}")]
    Jwt(String),
    /// HTTP transport error talking to the Fireblocks API.
    #[error("http: {0}")]
    Http(String),
    /// Fireblocks returned a non-success status or an error body.
    #[error("fireblocks api: {0}")]
    Api(String),
    /// A response body could not be deserialized into the expected shape.
    #[error("decode response: {0}")]
    Decode(String),
    /// Transaction construction (selection / change / sighash) failed.
    #[error("tx build: {0}")]
    TxBuild(String),
    /// Witness assembly from a returned signature failed.
    #[error("witness: {0}")]
    Witness(String),
    /// A signing request did not reach a usable signed state within the allotted time.
    #[error("signing timed out for tx {0}")]
    SigningTimeout(String),
}

/// A Fireblocks-backed general wallet.
///
/// Holds the REST client + signing material and a cached snapshot of the vault's unspent
/// inputs (refreshed by [`sync`](super::GeneralWallet::sync)).
pub struct FireblocksGeneralWallet {
    config: FireblocksConfig,
    http: reqwest::Client,
    /// RS256 signing key derived from the operator's Fireblocks API secret. Used to mint the
    /// per-request JWT.
    signing_key: jsonwebtoken::EncodingKey,
    /// Receive script derived from `config.deposit_address`. Returned by `script_pubkey` and
    /// used for change outputs.
    script_pubkey: ScriptBuf,
    /// Snapshot of the vault's spendable UTXOs from the most recent `sync`.
    cached_utxos: Vec<super::UtxoInfo>,
}

impl fmt::Debug for FireblocksGeneralWallet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FireblocksGeneralWallet")
            .field("config", &self.config)
            .field("signing_key", &"<redacted>")
            .field("script_pubkey", &self.script_pubkey)
            .field("cached_utxos", &self.cached_utxos.len())
            .finish()
    }
}

impl FireblocksGeneralWallet {
    /// Builds a Fireblocks general wallet from `config` and the operator's API secret
    /// (`api_secret_pem`, an RSA private key in PEM form used to sign request JWTs).
    ///
    /// Parses and network-checks the deposit address up-front so `script_pubkey` can be
    /// infallible. Does not perform any network I/O — call
    /// [`sync`](super::GeneralWallet::sync) to populate the UTXO cache.
    pub fn new(config: FireblocksConfig, api_secret_pem: &[u8]) -> Result<Self, FireblocksError> {
        let signing_key = jsonwebtoken::EncodingKey::from_rsa_pem(api_secret_pem)
            .map_err(|e| FireblocksError::SigningKey(e.to_string()))?;

        let address = config
            .deposit_address
            .parse::<Address<NetworkUnchecked>>()
            .map_err(|e| FireblocksError::DepositAddress(e.to_string()))?
            .require_network(config.network)
            .map_err(|e| FireblocksError::DepositAddress(e.to_string()))?;
        let script_pubkey = address.script_pubkey();

        Ok(Self {
            config,
            http: reqwest::Client::new(),
            signing_key,
            script_pubkey,
            cached_utxos: Vec::new(),
        })
    }

    /// Builds the full request URL and the matching JWT `uri` claim for an API `subpath`
    /// (the part after `/v1`, e.g. `/vault/accounts/0/BTC/unspent_inputs`).
    fn url_and_uri(&self, subpath: &str) -> (String, String) {
        let uri = format!("/v1{subpath}");
        let url = format!("{}{}", self.config.base_url, uri);
        (url, uri)
    }

    /// Issues an authenticated request to `subpath` and deserializes the JSON response into
    /// `T`. `body` is the request body for `POST`/`PUT` (the same bytes are hashed into the
    /// JWT); pass `None` for bodyless `GET`s.
    ///
    /// Non-2xx responses surface as [`FireblocksError::Api`] carrying the status + body;
    /// deserialization failures as [`FireblocksError::Decode`].
    async fn signed_request<T: DeserializeOwned>(
        &self,
        method: Method,
        subpath: &str,
        body: Option<&str>,
    ) -> Result<T, FireblocksError> {
        let (url, uri) = self.url_and_uri(subpath);
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
            return Err(FireblocksError::Api(format!("{status}: {text}")));
        }
        serde_json::from_str(&text)
            .map_err(|e| FireblocksError::Decode(format!("{e}; body={text}")))
    }

    /// Converts a Fireblocks unspent-input record into a backend-neutral [`UtxoInfo`],
    /// deriving the `script_pubkey` from the record's address.
    fn unspent_to_utxo_info(
        &self,
        u: &dto::UnspentInputsResponse,
    ) -> Result<UtxoInfo, FireblocksError> {
        let txid = Txid::from_str(&u.input.tx_hash)
            .map_err(|e| FireblocksError::Decode(format!("bad txHash {}: {e}", u.input.tx_hash)))?;
        let amount = Amount::from_str_in(&u.amount, Denomination::Bitcoin)
            .map_err(|e| FireblocksError::Decode(format!("bad amount {}: {e}", u.amount)))?;
        let script_pubkey = u
            .address
            .parse::<Address<NetworkUnchecked>>()
            .map_err(|e| FireblocksError::Decode(format!("bad address {}: {e}", u.address)))?
            .require_network(self.config.network)
            .map_err(|e| {
                FireblocksError::Decode(format!("address {} wrong network: {e}", u.address))
            })?
            .script_pubkey();
        // Fireblocks reports confirmations as an unbounded integer; clamp to u32 (the depth at
        // which the exact count stops mattering for any bridge predicate).
        let confirmations = u32::try_from(u.confirmations).unwrap_or(u32::MAX);
        Ok(UtxoInfo {
            outpoint: OutPoint {
                txid,
                vout: u.input.index,
            },
            amount,
            confirmations,
            script_pubkey,
        })
    }
}

impl GeneralWallet for FireblocksGeneralWallet {
    type Error = FireblocksError;

    async fn sync(&mut self) -> Result<(), Self::Error> {
        let subpath = format!(
            "/vault/accounts/{}/{}/unspent_inputs",
            self.config.vault_account_id, self.config.asset_id
        );
        let resp: dto::GetUnspentInputsResponse =
            self.signed_request(Method::GET, &subpath, None).await?;
        self.cached_utxos = resp
            .iter()
            .map(|u| self.unspent_to_utxo_info(u))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(())
    }

    fn script_pubkey(&self) -> ScriptBuf {
        self.script_pubkey.clone()
    }

    fn list_utxos(&self) -> Vec<UtxoInfo> {
        self.cached_utxos.clone()
    }

    async fn fund_v3_transaction(
        &mut self,
        _outputs: Vec<TxOut>,
        _explicit_inputs: Option<&[OutPoint]>,
        _fee_rate: FeeRate,
        _exclude: &[OutPoint],
    ) -> Result<FundedPsbt, Self::Error> {
        // TODO(STR-3434 Fireblocks): build unsigned v3 tx, RAW-sign via Fireblocks, assemble
        // P2WPKH witnesses. Tracked by tasks #16/#17.
        Err(FireblocksError::TxBuild(
            "fund_v3_transaction not yet implemented".to_string(),
        ))
    }

    async fn build_cpfp_child(
        &mut self,
        _parent: &Transaction,
        _parent_fee: Amount,
        _anchor: AnchorInfo,
        _target_pkg_fee_rate: FeeRate,
        _exclude: &[OutPoint],
    ) -> Result<FundedPsbt, Self::Error> {
        // TODO(STR-3434 Fireblocks): build CPFP child (anchor input left unsigned for s2,
        // funding input RAW-signed by Fireblocks). Tracked by tasks #16/#17.
        Err(FireblocksError::TxBuild(
            "build_cpfp_child not yet implemented".to_string(),
        ))
    }
}
