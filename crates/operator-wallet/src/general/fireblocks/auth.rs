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
//!   `iat + TOKEN_TTL_SECS` (a few seconds under that ceiling to absorb clock skew).
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

/// JWT token lifetime. Fireblocks rejects tokens whose `exp - iat` exceeds ~30s, so we stay a
/// few seconds under that ceiling to absorb clock skew and request-flight time.
const TOKEN_TTL_SECS: u64 = 25;

/// Per-process counter that disambiguates tokens minted at the same clock reading.
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
        nonce: next_nonce(),
        iat: now_secs,
        exp: now_secs + TOKEN_TTL_SECS,
        sub: api_key.to_string(),
        body_hash: body_hash(body),
    }
}

/// Produces a per-request nonce: the nanosecond wall clock plus a process-monotonic counter.
///
/// The nanosecond base makes nonces unique across process restarts (a fresh process reads a
/// later clock), while the counter disambiguates requests that read the same nanosecond. A
/// counter-only scheme would reset to 0 on restart and could replay a nonce within
/// Fireblocks' validity window, getting the request rejected.
fn next_nonce() -> u64 {
    // Truncating u128 nanos to u64 is intentional and harmless: it only needs to be unique
    // within Fireblocks' short validity window, and the counter disambiguates ties. u64 nanos
    // don't wrap until ~year 2554.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    nanos.wrapping_add(counter)
}

#[cfg(test)]
mod tests {
    use jsonwebtoken::{DecodingKey, Validation};

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
    fn nonces_are_unique_across_rapid_calls() {
        // Rapid calls may read the same nanosecond; the counter must disambiguate them.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..10_000 {
            assert!(seen.insert(next_nonce()), "nonce collision");
        }
    }

    /// Throwaway 2048-bit RSA key pair (PKCS#8 / SPKI PEM), not a secret. It exists only to
    /// pin the `jsonwebtoken` crypto provider: with no provider feature compiled in,
    /// the default provider's signer factory panics on the first `encode` call.
    const TEST_RSA_PRIVATE_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCMNfum0ipMfWIS
eowAEix26JaYdgLNzn/xQUMBNmRJFe4Fx308Du/8UJcqrl1L2daqU3oAvtZxl7jI
S9qXHGbCbGNyAypL/BR69xKVZJi8FGH6rJyN+dI1xW/CbnOo9w96ZotxM43XGofF
0zOd3pAfICrH5hmCvx+bRH7zOYJAKve6G8lZGS6F57spgv2Ez+3Y0rXTkTJoEw47
X6kdsouRZzD2KxMzzZGtAxG2mIzjozQCokb8RBxpQeytQwg4Tnm5uLIr/IrKOs9q
XXaHyiO+hvj3iBzQbb4vPdIOh719vmAlmZOskDRKe9Y2lVJqlLZJohTirRf2eRb1
lkJE+PdTAgMBAAECggEANnHl6Nb2TuJnOUa143crJfdWNxioKRO1MdEGPEvLMGgg
F8Vpl28zeFYxBQVVPBV4WoZ0uyJfshdYzQpLdN819exRx118SKo3p7IWWMWJ24rM
qyLo3eay3mdu6OCr7+IT9BMqtYfv3aWzMDm9cuGQNE3w3tO2d0NQ+iFkbH0Z22Fg
wRP+QyTXEBK/k+lIsCPAmiytjUPwOeO6p3dfbyGKtBE894oZ8d/LH03FV6vPRRYY
rBDmN3MOO6jZ3fg2MsllbFwDmqX1UQT9+5EWdZAwXYm/nv544aGZL/P7hMjSUdev
9xi8mMu9pG41+6/HpVe7hCBeJoHJodCrO1hcFX8xNQKBgQDDUJThjwH89HnqyBr4
RBcAc8eDquIRgV2CyJ5oU5WGs0ErLf8HAklXo9MDf1dMBGKY1NNfhVx84PZFCQiG
lb3H3CevRm+a1HE10XyZWCD47g1VPk3SFQsRUVtaRdwxd9bXF6ACBaQ3ugkXw+N0
5bMihRfBdw00zuZE3QzdrHv8nwKBgQC3xmoJQtlmn3gMTGnZsNdrnMVOGEWmPfYB
eYt4hjjI9QZE8q2MlqhdmGlQGzo+FOQhnjAEGwDQwGRD5eV4snfn7tL/R1VmJld9
Wr1sjE6/c6O9+0SA6/AfyUvNMljbR8ygyDwyQdXQ5OOwLfsChZYoRJlut9yBMZ61
6K1zugTUzQKBgAg/C7omPpA+hjM6daELxujW+pJ9kYPpsVgHPmDrPoHsaZD4JS9X
kl8n5I3eP4JPIRaQzcfXqpr/KIarpfeAtP2ONwK4d5fS5mC+UoNq7CF2c4uo0MJQ
7yGxDKlYD77q72AveCr9r/xGV4HwXFcgJ5sKgYFClIUpQyGfL57gXG/DAoGATtgU
ZBbHGM0v/u7Ftvy031lqGQA22YTZx3YzDSlgsW7WGryXEqsMXuNlw1V7HmluGrI4
XXqMVgNEwRCf67F92gbPhXBARkwK2yAUBr8HhgIB7R8hG8KdybVeDRIdpy5dr1lY
4iL2reGVgd+oQkO30VzlCuhc9Rypv9esmuri6b0CgYEAnts5srGMWKsT+yyMRuyd
knTG8XP5pEbxVCbdV2b6t5BlqaWWdWX6n+uZPlOTXJfcLVe5n7LMpWg4FVTnfuje
afEvdqCMi8LXMu7558emcDGHDCvXt9OBO/aSsjEPAWtBT+g4bqHTSSdLaRhYqyj4
xib2bRSsBtnKKKFsk4Rr09g=
-----END PRIVATE KEY-----
"#;
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

    #[test]
    fn build_jwt_signs_and_verifies() {
        let signing_key = EncodingKey::from_rsa_pem(TEST_RSA_PRIVATE_PEM.as_bytes())
            .expect("test key must parse");

        let uri = "/v1/vault/accounts/0/BTC/unspent_inputs";
        let token = build_jwt(uri, b"", "test-api-key", &signing_key)
            .expect("encode panics if no jsonwebtoken provider is compiled in");

        let verification_key =
            DecodingKey::from_rsa_pem(TEST_RSA_PUBLIC_PEM.as_bytes()).expect("test key must parse");
        let data = jsonwebtoken::decode::<serde_json::Value>(
            &token,
            &verification_key,
            &Validation::new(Algorithm::RS256),
        )
        .expect("the RS256 signature must verify against the public key");

        assert_eq!(data.claims["uri"], uri);
        assert_eq!(data.claims["sub"], "test-api-key");
    }
}
