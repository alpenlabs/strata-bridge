//! Test helpers shared by the Fireblocks submodules: the vault key, signers, and mock responses.

use bdk_wallet::bitcoin::secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
use serde_json::json;
use wiremock::{
    matchers::{method, path},
    Mock, MockServer, ResponseTemplate,
};

use super::{FireblocksConfig, FireblocksSigner};
use crate::test_utils::TEST_RSA_PRIVATE_PEM;

pub(super) const VAULT_SECRET: [u8; 32] = [7; 32];
pub(super) const TX_ID: &str = "tx-1";
pub(super) const TX_PATH: &str = "/v1/transactions/tx-1";
pub(super) const CREATE_PATH: &str = "/v1/transactions";

pub(super) fn vault_pubkey() -> PublicKey {
    let secret = SecretKey::from_slice(&VAULT_SECRET).expect("valid scalar");
    secret.public_key(&Secp256k1::new())
}

pub(super) fn config(base_url: &str) -> FireblocksConfig {
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
pub(super) fn offline_signer() -> FireblocksSigner {
    FireblocksSigner::build(
        config("http://127.0.0.1:9/"),
        TEST_RSA_PRIVATE_PEM.as_bytes(),
    )
    .expect("valid config")
}

/// A signer on a mock server, which speaks plain HTTP.
pub(super) fn mock_signer(server: &MockServer) -> FireblocksSigner {
    FireblocksSigner::build(config(&server.uri()), TEST_RSA_PRIVATE_PEM.as_bytes())
        .expect("valid config")
}

/// A transaction detail body with signatures over `signed`, from `secret`.
pub(super) fn details(status: &str, signed: &[[u8; 32]], secret: &[u8; 32]) -> serde_json::Value {
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
pub(super) async fn expect(
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

pub(super) fn ok(body: serde_json::Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(body)
}

pub(super) fn created() -> ResponseTemplate {
    ok(json!({ "id": TX_ID }))
}
