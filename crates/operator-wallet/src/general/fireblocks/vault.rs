//! The startup check of a Fireblocks vault, and the value that proves it ran.

use std::{str::FromStr, time::Instant};

use bdk_wallet::{
    bitcoin::secp256k1::PublicKey, descriptor, descriptor::ExtendedDescriptor, miniscript,
};
use reqwest::Method;
use sha2::{Digest, Sha256};

use super::{
    dto, raw::SIGN_MAX_DURATION, sign, FireblocksError, FireblocksSigner, StartupCheckError,
};
use crate::persist::WalletStore;

/// The self-test digest is the SHA-256 of this tag. A BIP-143 sighash is a double SHA-256, so it
/// can equal this digest only if an inner hash equals the tag, and the tag is not 32 bytes long.
/// The signature that the self-test obtains therefore authorizes no spend.
const SELF_TEST_TAG: &[u8] = b"strata-bridge/operator-wallet/fireblocks/self-test";

impl FireblocksSigner {
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

    /// Compares the public key of the vault address with
    /// [`FireblocksConfig::vault_pubkey`](super::FireblocksConfig::vault_pubkey). The
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
    /// equal [`FireblocksConfig::vault_pubkey`](super::FireblocksConfig::vault_pubkey). Then a RAW
    /// request must sign a fixed digest, and the signature and the signing key must verify
    /// against the vault script. Any failure is an error, an API outage too: a pass would
    /// persist a descriptor that nothing has checked. A RAW request that waits for a human
    /// fails it.
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
    #[expect(
        dead_code,
        reason = "used by the commit that holds the general funds in a Fireblocks vault"
    )]
    pub(in crate::general) fn into_parts(self) -> (ExtendedDescriptor, FireblocksSigner, P) {
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
    use bdk_wallet::bitcoin::secp256k1::{Secp256k1, SecretKey};
    use serde_json::json;
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, Request, ResponseTemplate,
    };

    use super::*;
    use crate::{
        general::fireblocks::test_utils::{
            created, details, expect, mock_signer, offline_signer, ok, vault_pubkey, CREATE_PATH,
            TX_PATH, VAULT_SECRET,
        },
        test_utils::MemoryStore,
    };

    /// Public half of [`TEST_RSA_PRIVATE_PEM`](crate::test_utils::TEST_RSA_PRIVATE_PEM).
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
            // A request with no body signs the JSON encoding of an empty string.
            let signed_body: &[u8] = if request.body.is_empty() {
                br#""""#
            } else {
                &request.body
            };
            assert_eq!(
                claims["bodyHash"],
                hex::encode(Sha256::digest(signed_body)),
                "the JWT signs the body that was sent"
            );
            assert_eq!(
                claims["sub"],
                request.headers["x-api-key"].to_str().expect("ascii header")
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
}
