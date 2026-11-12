//! The authenticated HTTP client of the Fireblocks API.

use std::{fmt, sync::Arc, time::Duration};

use bdk_wallet::bitcoin::{CompressedPublicKey, ScriptBuf};
use reqwest::Method;
use serde::de::DeserializeOwned;

use super::{auth, FireblocksConfig, FireblocksError, FireblocksInitError};

/// Per-request HTTP timeout. Without it a hung Fireblocks endpoint would stall a request
/// indefinitely: a hang is not an `Err`, and the deadline is read between polls, so it could wedge
/// the signing loop past [`SIGN_MAX_DURATION`](super::raw::SIGN_MAX_DURATION). Kept comfortably
/// above normal latency but bounded.
pub(super) const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The client of a Fireblocks vault. It signs inputs that spend the vault script.
///
/// A caller takes a clone from the wallet and holds no wallet lock while it waits for a signature.
/// [`GeneralSigner`](crate::general::GeneralSigner) holds this type by value, so the `Arc`s keep
/// that enum in the limits of `clippy::large_enum_variant`.
#[derive(Clone)]
pub struct FireblocksSigner {
    pub(super) config: Arc<FireblocksConfig>,
    http: reqwest::Client,
    /// RS256 signing key derived from the operator's Fireblocks API secret. Used to mint the
    /// per-request JWT.
    signing_key: Arc<jsonwebtoken::EncodingKey>,
    /// The P2WPKH script of [`FireblocksConfig::vault_pubkey`]. This signer signs only inputs
    /// that spend it.
    pub(super) script_pubkey: ScriptBuf,
    /// The first generation that a request for a sighash set (by digest) can still take, as this
    /// process last saw it. Every attempt would otherwise walk the ended generations from zero,
    /// two calls each, against the signing deadline. The map lives for the process; a restart
    /// walks once more.
    pub(super) generations: Arc<std::sync::Mutex<std::collections::HashMap<String, u64>>>,
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
    pub(super) fn build(
        config: FireblocksConfig,
        api_secret_pem: &[u8],
    ) -> Result<Self, FireblocksInitError> {
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
    pub(super) async fn signed_request<T: DeserializeOwned>(
        &self,
        method: Method,
        subpath: &str,
        body: Option<&str>,
    ) -> Result<T, FireblocksError> {
        // The JWT `uri` claim and the request URL share one string, so they cannot drift apart.
        let uri = format!("/v1{subpath}");
        let url = format!("{}{uri}", self.config.base_url);
        let jwt = auth::build_jwt(
            &uri,
            signed_body(body),
            &self.config.api_key,
            &self.signing_key,
        )?;

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
}

/// The bytes that the JWT `bodyHash` of a request covers. A request with no body signs the JSON
/// encoding of an empty string, `""`, as Fireblocks' own clients do.
fn signed_body(body: Option<&str>) -> &[u8] {
    body.map_or(br#""""#, str::as_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{general::fireblocks::test_utils::config, test_utils::TEST_RSA_PRIVATE_PEM};

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

    /// A stray slash in the path would make Fireblocks reject the JWT `uri` claim.
    #[test]
    fn a_trailing_slash_leaves_the_base_url_bare() {
        let base = parse_base_url("https://api.fireblocks.io/").expect("valid");
        assert_eq!(base, "https://api.fireblocks.io");
    }

    /// Fireblocks' own clients sign a request with no body over `JSON.stringify("")`.
    #[test]
    fn a_request_with_no_body_signs_the_json_of_an_empty_string() {
        assert_eq!(
            signed_body(None),
            br#""""#,
            "a bodyless request signs the two-byte string of quotes"
        );
        assert_eq!(
            signed_body(Some("{}")),
            b"{}",
            "a request with a body signs the body as sent"
        );
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
}
