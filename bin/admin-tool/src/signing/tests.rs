use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin::{
    absolute,
    hashes::{sha256, Hash},
    secp256k1::{schnorr, Keypair, Message, SECP256K1},
    transaction::Version,
    Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
};
use strata_bridge_connectors::{prelude::ClaimPayoutConnector, Connector};

use super::{SigningParams, SigningRequest, ADMIN_SIGHASH_TYPE};
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
async fn signs_with_the_matching_admin_and_exports_the_sighash_byte() {
    let request = request();
    let signer = TestSigner::new(2);

    let signature = request.sign(&signer, signer.public_key).await.unwrap();
    assert_eq!(signature.pubkey_index, 1);
    assert_eq!(signature.signature.sighash_type, ADMIN_SIGHASH_TYPE);

    let encoded = signature.signature.serialize();
    assert_eq!(encoded.len(), 65);
    assert_eq!(encoded[64], 0x82);
    SECP256K1
        .verify_schnorr(
            &signature.signature.signature,
            &Message::from_digest(request.digest()),
            &signer.public_key,
        )
        .unwrap();
}

#[tokio::test]
async fn rejects_an_unknown_admin_before_requesting_a_signature() {
    let signer = TestSigner::new(9);

    let error = request()
        .sign(&signer, signer.public_key)
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
        .sign(&signer, signer.public_key)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("returned an invalid signature"));
}

#[tokio::test]
async fn signature_cannot_authorize_a_different_claim() {
    let params = params();
    let mut claim = claim(&params);
    let first = SigningRequest::new(claim.compute_txid(), &claim, params.clone()).unwrap();
    let signer = TestSigner::new(1);
    let signature = first.sign(&signer, signer.public_key).await.unwrap();

    // Preserve the same payout connector while changing which claim creates it.
    claim.input[0].previous_output.vout += 1;
    let other = SigningRequest::new(claim.compute_txid(), &claim, params).unwrap();

    assert_ne!(first.digest(), other.digest());
    assert!(SECP256K1
        .verify_schnorr(
            &signature.signature.signature,
            &Message::from_digest(other.digest()),
            &signer.public_key
        )
        .is_err());
}
