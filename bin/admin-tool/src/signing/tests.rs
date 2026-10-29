use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin::{
    absolute,
    hashes::{sha256, Hash},
    hex::DisplayHex,
    secp256k1::{schnorr, Keypair, Message, SECP256K1},
    transaction::Version,
    Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
};
use strata_bridge_connectors::{prelude::ClaimPayoutConnector, Connector};

use super::{SigningParams, SigningRequest};
use crate::signer::AdminSigner;

fn keypair(byte: u8) -> Keypair {
    Keypair::from_seckey_slice(SECP256K1, &[byte; 32]).unwrap()
}

fn params() -> SigningParams {
    SigningParams {
        network: Network::Regtest,
        n_of_n_pubkey: keypair(4).x_only_public_key().0,
        admin_pubkeys: (1..=3).map(|i| keypair(i).x_only_public_key().0).collect(),
        threshold: 2,
        unstaking_hash: sha256::Hash::hash(&[5; 32]),
    }
}

// Only the payout output matters here. The CLI checks chain status separately.
fn claim(params: &SigningParams) -> Transaction {
    let connector = ClaimPayoutConnector::new(
        params.network,
        params.n_of_n_pubkey,
        params.admin_pubkeys.clone(),
        params.threshold,
        params.unstaking_hash,
    );

    Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([6; 32]), 0),
            ..Default::default()
        }],
        output: vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new_op_return([]),
            },
            connector.tx_out(),
        ],
    }
}

fn request() -> SigningRequest {
    let params = params();
    let claim = claim(&params);

    SigningRequest::new(claim.compute_txid(), &claim, params).unwrap()
}

struct TestSigner {
    public_key: XOnlyPublicKey,
    signing_key: Keypair,
    signing_called: AtomicBool,
}

impl TestSigner {
    fn new(byte: u8) -> Self {
        let signing_key = keypair(byte);

        Self {
            public_key: signing_key.x_only_public_key().0,
            signing_key,
            signing_called: AtomicBool::new(false),
        }
    }
}

impl AdminSigner for TestSigner {
    async fn public_key(&self) -> anyhow::Result<XOnlyPublicKey> {
        Ok(self.public_key)
    }

    async fn sign_digest(&self, digest: [u8; 32]) -> anyhow::Result<schnorr::Signature> {
        self.signing_called.store(true, Ordering::Relaxed);

        Ok(SECP256K1.sign_schnorr_no_aux_rand(&Message::from_digest(digest), &self.signing_key))
    }
}

#[test]
fn rejects_invalid_admin_sets_without_panicking() {
    let params = params();
    let claim = claim(&params);
    let txid = claim.compute_txid();

    let mut empty = params.clone();
    empty.admin_pubkeys.clear();

    let error = SigningRequest::new(txid, &claim, empty).unwrap_err();

    assert!(error.to_string().contains("admin set must not be empty"));

    for threshold in [0, params.admin_pubkeys.len() + 1] {
        let mut invalid = params.clone();
        invalid.threshold = threshold;

        let error = SigningRequest::new(txid, &claim, invalid).unwrap_err();

        assert!(error
            .to_string()
            .contains("admin threshold must be between"));
    }

    let mut duplicate = params.clone();
    duplicate.admin_pubkeys[1] = duplicate.admin_pubkeys[0];

    let error = SigningRequest::new(txid, &claim, duplicate).unwrap_err();

    assert!(error.to_string().contains("duplicate admin public key"));
}

#[test]
fn rejects_a_different_claim_or_missing_payout() {
    let params = params();
    let mut claim = claim(&params);

    let error =
        SigningRequest::new(Txid::from_byte_array([7; 32]), &claim, params.clone()).unwrap_err();

    assert!(error
        .to_string()
        .contains("does not match the requested txid"));

    claim.output.truncate(1);
    let error = SigningRequest::new(claim.compute_txid(), &claim, params).unwrap_err();

    assert!(error.to_string().contains("no payout output at index 1"));
}

#[test]
fn rejects_parameters_that_do_not_match_the_claim_script() {
    let params = params();
    let claim = claim(&params);
    let txid = claim.compute_txid();

    let mut reordered = params.clone();
    reordered.admin_pubkeys.swap(0, 1);

    let mut wrong_threshold = params.clone();
    wrong_threshold.threshold = 1;

    let mut wrong_hash = params.clone();
    wrong_hash.unstaking_hash = sha256::Hash::hash(&[8; 32]);

    let mut wrong_internal_key = params;
    wrong_internal_key.n_of_n_pubkey = keypair(9).x_only_public_key().0;

    for mismatched in [reordered, wrong_threshold, wrong_hash, wrong_internal_key] {
        let error = SigningRequest::new(txid, &claim, mismatched).unwrap_err();

        assert!(error.to_string().contains("does not match claim output 1"));
    }
}

#[test]
fn rejects_an_unexpected_connector_amount() {
    let params = params();
    let mut claim = claim(&params);
    claim.output[1].value += Amount::ONE_SAT;

    let error = SigningRequest::new(claim.compute_txid(), &claim, params).unwrap_err();

    assert!(error.to_string().contains("claim payout value is"));
}

#[tokio::test]
async fn rejects_an_unknown_admin_before_requesting_a_signature() {
    let signer = TestSigner::new(9);

    let error = request()
        .sign_and_verify(&signer, signer.public_key)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("not in the admin set"));
    assert!(!signer.signing_called.load(Ordering::Relaxed));
}

#[tokio::test]
async fn rejects_a_backend_signature_from_a_different_key() {
    let mut signer = TestSigner::new(1);
    signer.signing_key = keypair(2);

    let error = request()
        .sign_and_verify(&signer, signer.public_key)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("returned an invalid signature"));
}

#[tokio::test]
async fn assembly_identifies_signers_and_rejects_invalid_or_repeated_signatures() {
    let params = params();
    let mut claim = claim(&params);
    let request = SigningRequest::new(claim.compute_txid(), &claim, params.clone()).unwrap();

    let mut signatures = Vec::new();
    for byte in [1, 3] {
        let signer = TestSigner::new(byte);
        let signature = request
            .sign_and_verify(&signer, signer.public_key)
            .await
            .unwrap();
        signatures.push(signature.serialize().to_lower_hex_string());
    }

    assert!(request.assemble(&signatures[..1]).is_err());
    assert!(request
        .assemble(&[signatures[0].clone(), signatures[0].clone()])
        .is_err());

    for invalid in [
        "not hex".to_owned(),
        "00".repeat(65),
        signatures[0][..128].to_owned(),
        format!("{}02", &signatures[0][..128]),
    ] {
        let error = request
            .assemble(&[signatures[1].clone(), invalid])
            .unwrap_err();

        assert!(error.to_string().starts_with("signature #2:"));
    }

    // The same connector on another claim must not accept these signatures.
    claim.input[0].previous_output.vout += 1;
    let other = SigningRequest::new(claim.compute_txid(), &claim, params).unwrap();

    assert!(other.assemble(&signatures).is_err());

    let unknown = TestSigner::new(9)
        .sign_digest(request.digest())
        .await
        .unwrap();
    let encoded = format!("{}82", unknown.serialize().to_lower_hex_string());

    assert!(request.assemble(&[encoded, signatures[1].clone()]).is_err());

    // Even different valid signatures from one admin cannot count twice.
    let repeated = SECP256K1.sign_schnorr_with_aux_rand(
        &Message::from_digest(request.digest()),
        &keypair(1),
        &[42; 32],
    );
    let encoded = format!("{}82", repeated.serialize().to_lower_hex_string());
    let error = request
        .assemble(&[signatures[0].clone(), encoded])
        .unwrap_err();

    assert!(error
        .to_string()
        .starts_with("signature #2: duplicate admin signature"));

    // A and C sign; B's slot stays empty regardless of the CLI argument order.
    let forward = request.assemble(&signatures).unwrap();
    let witness = forward.transaction.input[0].witness.to_vec();

    assert_eq!(forward.admin_indices, vec![0, 2]);
    assert_eq!(witness[0].to_lower_hex_string(), signatures[1]);
    assert!(witness[1].is_empty());
    assert_eq!(witness[2].to_lower_hex_string(), signatures[0]);

    signatures.reverse();
    signatures[0] = format!(" {}\n", signatures[0].to_uppercase());
    assert_eq!(request.assemble(&signatures).unwrap(), forward);

    // A third signature is valid but only the first two admins are included.
    let signer = TestSigner::new(2);
    let signature = request
        .sign_and_verify(&signer, signer.public_key)
        .await
        .unwrap();
    signatures.push(signature.serialize().to_lower_hex_string());
    let all_admins = request.assemble(&signatures).unwrap();

    assert_eq!(all_admins.admin_indices, vec![0, 1]);
    assert!(all_admins.transaction.input[0]
        .witness
        .iter()
        .next()
        .unwrap()
        .is_empty());
}
