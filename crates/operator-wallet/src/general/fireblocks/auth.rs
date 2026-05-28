//! Fireblocks request authentication: per-request RS256 JWT + body hashing.
//!
//! Every Fireblocks API call carries two credentials:
//! - `X-API-Key: <api key>` (added by the caller), and
//! - `Authorization: Bearer <JWT>`, where the JWT is RS256-signed with the operator's API secret
//!   (an RSA private key) and proves possession of that key plus integrity of the request body.
//!
//! ## Claims
//!
//! Per the Fireblocks API authentication scheme, the JWT carries:
//! - `uri`   — the request path **including query string**, host excluded (e.g.
//!   `/v1/vault/accounts/0/BTC/unspent_inputs`). Must match the request exactly.
//! - `nonce` — a value unique per request (replay protection).
//! - `iat`   — issued-at, unix seconds.
//! - `exp`   — expiry, unix seconds. Fireblocks rejects tokens valid for more than ~30s, so we use
//!   `iat + 30`.
//! - `sub`   — the API key.
//! - `bodyHash` — lowercase hex of `SHA256(raw request body)`. For bodyless requests (GET), this is
//!   the SHA256 of the empty string.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::FireblocksError;

/// JWT token lifetime. Fireblocks rejects tokens whose `exp - iat` exceeds ~30s.
const TOKEN_TTL_SECS: u64 = 30;

/// Monotonic component of the nonce, bumped once per minted token so two tokens minted within
/// the same second (or at the same instant on a coarse clock) still differ.
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The Fireblocks JWT claim set. Field names match the wire format exactly.
#[derive(Debug, Serialize)]
struct Claims {
    uri: String,
    nonce: u64,
    iat: u64,
    exp: u64,
    sub: String,
    #[serde(rename = "bodyHash")]
    body_hash: String,
}

/// Lowercase-hex SHA256 of `body`. For GET/bodyless requests pass an empty slice.
pub(super) fn body_hash(body: &[u8]) -> String {
    let digest = Sha256::digest(body);
    hex::encode(digest)
}

/// Builds a signed RS256 JWT for a request to `uri` carrying `body`.
///
/// `uri` is the path + query string with the host excluded (e.g.
/// `/v1/vault/accounts/0/BTC/unspent_inputs`). `api_key` becomes the `sub` claim. `signing_key`
/// is the RS256 key built from the operator's API secret PEM.
pub(super) fn build_jwt(
    uri: &str,
    body: &[u8],
    api_key: &str,
    signing_key: &EncodingKey,
) -> Result<String, FireblocksError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| FireblocksError::Jwt(format!("system clock before unix epoch: {e}")))?
        .as_secs();

    let claims = build_claims(uri, body, api_key, now);

    jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, signing_key)
        .map_err(|e| FireblocksError::Jwt(e.to_string()))
}

/// Assembles the Fireblocks claim set for a request. Pure (no signing, no clock read) so the
/// claim-construction logic — `uri`, `bodyHash`, the `iat`/`exp` window, the per-request nonce
/// — can be unit-tested without any key material. The RS256 signing itself is delegated to
/// `jsonwebtoken::encode` in [`build_jwt`].
fn build_claims(uri: &str, body: &[u8], api_key: &str, now_secs: u64) -> Claims {
    Claims {
        uri: uri.to_string(),
        nonce: next_nonce(now_secs),
        iat: now_secs,
        exp: now_secs + TOKEN_TTL_SECS,
        sub: api_key.to_string(),
        body_hash: body_hash(body),
    }
}

/// Produces a per-request nonce. Combines the current unix-second with a process-monotonic
/// counter so concurrent or rapid requests never collide on the same value.
fn next_nonce(now_secs: u64) -> u64 {
    let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    // Shift the second into the high bits and OR in the counter's low bits. The counter wraps
    // far beyond any realistic per-second request volume, so collisions are impossible in
    // practice within a token's 30s validity window.
    (now_secs << 20) ^ counter
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_hash_matches_known_vectors() {
        // SHA256("") and SHA256("hello") — fixed reference values.
        assert_eq!(
            body_hash(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            body_hash(b"hello"),
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn claims_carry_expected_fields_and_window() {
        let uri = "/v1/vault/accounts/0/BTC/unspent_inputs";
        let api_key = "test-api-key";
        let now = 1_700_000_000;

        let claims = build_claims(uri, b"", api_key, now);

        assert_eq!(claims.uri, uri);
        assert_eq!(claims.sub, api_key);
        // bodyHash of an empty body is SHA256("").
        assert_eq!(
            claims.body_hash,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(claims.iat, now);
        assert_eq!(claims.exp - claims.iat, TOKEN_TTL_SECS);
    }

    #[test]
    fn nonces_are_unique_within_the_same_second() {
        // The risky case is many requests minted in the same unix-second: the monotonic
        // counter must disambiguate them.
        let now = 1_700_000_000;
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(
                seen.insert(next_nonce(now)),
                "nonce collision within one second"
            );
        }
    }
}
