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
//!   `/v1/transactions`). Must match the request exactly.
//! - `nonce` — a string unique per request (replay protection).
//! - `iat`   — issued-at, unix seconds.
//! - `exp`   — expiry, unix seconds. Fireblocks rejects tokens valid for more than ~30s, so we use
//!   `iat + TOKEN_TTL_SECS` (a few seconds under that ceiling to absorb clock skew).
//! - `sub`   — the API key.
//! - `bodyHash` — lowercase hex of `SHA256` over the bytes that the caller signs: the request body,
//!   or the JSON encoding of an empty string for a request with no body.

use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::Serialize;
use sha2::{Digest, Sha256};

use super::FireblocksError;

/// JWT token lifetime. Fireblocks rejects tokens whose `exp - iat` exceeds ~30s, so we stay a
/// few seconds under that ceiling to absorb clock skew and request-flight time.
const TOKEN_TTL_SECS: u64 = 25;

/// Per-process counter that disambiguates tokens minted at the same clock reading.
static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// The Fireblocks JWT claim set. Field names match the wire format exactly.
#[derive(Debug, Serialize)]
struct Claims {
    uri: String,
    nonce: String,
    iat: u64,
    exp: u64,
    sub: String,
    #[serde(rename = "bodyHash")]
    body_hash: String,
}

/// Builds a signed RS256 JWT for a request to `uri` carrying `body`.
///
/// `uri` is the path + query string with the host excluded (e.g.
/// `/v1/transactions`). `api_key` becomes the `sub` claim. `signing_key`
/// is the RS256 key built from the operator's API secret PEM.
pub(super) fn build_jwt(
    uri: &str,
    body: &[u8],
    api_key: &str,
    signing_key: &EncodingKey,
) -> Result<String, FireblocksError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| FireblocksError::Jwt(format!("system clock before unix epoch: {e}")))?;

    let claims = build_claims(uri, body, api_key, now.as_secs(), next_nonce(now));

    jsonwebtoken::encode(&Header::new(Algorithm::RS256), &claims, signing_key)
        .map_err(|e| FireblocksError::Jwt(e.to_string()))
}

/// Assembles the Fireblocks claim set for a request. Pure (no signing, no clock read) so the
/// claim-construction logic — `uri`, `bodyHash`, the `iat`/`exp` window — can be unit-tested
/// without any key material. The RS256 signing itself is delegated to `jsonwebtoken::encode` in
/// [`build_jwt`].
fn build_claims(uri: &str, body: &[u8], api_key: &str, now_secs: u64, nonce: String) -> Claims {
    Claims {
        uri: uri.to_string(),
        nonce,
        iat: now_secs,
        exp: now_secs + TOKEN_TTL_SECS,
        sub: api_key.to_string(),
        body_hash: hex::encode(Sha256::digest(body)),
    }
}

/// Produces a per-request nonce: the nanosecond wall clock and a process-monotonic counter.
///
/// The clock part makes nonces unique across process restarts (a fresh process reads a later
/// clock), while the counter disambiguates requests that read the same nanosecond. A counter-only
/// scheme would reset to 0 on restart and could replay a nonce within Fireblocks' validity window,
/// getting the request rejected.
///
/// The nonce is a string, because this value does not fit in a JSON number without loss on a
/// server that parses numbers as doubles.
fn next_nonce(now: Duration) -> String {
    let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{counter}", now.as_nanos())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_carry_expected_fields_and_window() {
        let uri = "/v1/transactions";
        let api_key = "test-api-key";
        let now = 1_700_000_000;

        let claims = build_claims(uri, b"", api_key, now, "nonce".to_string());

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
    fn nonces_are_unique_across_rapid_calls() {
        // Rapid calls may read the same nanosecond; the counter must disambiguate them.
        let now = Duration::from_secs(1_700_000_000);
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(next_nonce(now)), "nonce collision");
        }
    }
}
