use std::{
    convert::Infallible,
    sync::atomic::{AtomicBool, Ordering},
};

use bitcoin::{
    absolute,
    hashes::{sha256, Hash},
    secp256k1::{schnorr, Keypair, Message, SECP256K1},
    transaction::Version,
    Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
};
use strata_bridge_connectors::{prelude::ClaimPayoutConnector, Connector};

use crate::{
    AdminSigner, AdminSigningParams, AdminSigningRequest, RequestError, SigningError,
    ADMIN_SIGHASH_TYPE,
};

fn keypair(byte: u8) -> Keypair {
    Keypair::from_seckey_slice(SECP256K1, &[byte; 32]).unwrap()
}

fn params() -> AdminSigningParams {
    AdminSigningParams {
        network: Network::Regtest,
        n_of_n_pubkey: keypair(4).x_only_public_key().0,
        admin_pubkeys: (1..=3).map(|i| keypair(i).x_only_public_key().0).collect(),
        threshold: 2,
        unstaking_hash: sha256::Hash::hash(&[5; 32]),
    }
}

fn connector(params: &AdminSigningParams) -> ClaimPayoutConnector {
    ClaimPayoutConnector::new(
        params.network,
        params.n_of_n_pubkey,
        params.admin_pubkeys.clone(),
        params.threshold,
        params.unstaking_hash,
    )
}

// Only the target payout output is relevant to this library. Chain validity is a caller check.
fn claim(params: &AdminSigningParams) -> Transaction {
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
            connector(params).tx_out(),
        ],
    }
}

fn request() -> AdminSigningRequest {
    let params = params();
    let claim = claim(&params);
    AdminSigningRequest::new(claim.compute_txid(), &claim, params).unwrap()
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
    type Error = Infallible;

    async fn public_key(&self) -> Result<XOnlyPublicKey, Self::Error> {
        Ok(self.public_key)
    }

    async fn sign_digest(&self, digest: [u8; 32]) -> Result<schnorr::Signature, Self::Error> {
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
    assert!(matches!(
        AdminSigningRequest::new(txid, &claim, empty),
        Err(RequestError::EmptyAdminSet)
    ));

    for threshold in [0, params.admin_pubkeys.len() + 1] {
        let mut invalid = params.clone();
        invalid.threshold = threshold;
        assert!(matches!(
            AdminSigningRequest::new(txid, &claim, invalid),
            Err(RequestError::InvalidThreshold)
        ));
    }

    let mut duplicate = params.clone();
    duplicate.admin_pubkeys[1] = duplicate.admin_pubkeys[0];
    assert!(matches!(
        AdminSigningRequest::new(txid, &claim, duplicate),
        Err(RequestError::DuplicateAdminKey(key)) if key == params.admin_pubkeys[0]
    ));
}

#[test]
fn rejects_a_different_claim_or_missing_payout() {
    let params = params();
    let mut claim = claim(&params);
    assert!(matches!(
        AdminSigningRequest::new(Txid::from_byte_array([7; 32]), &claim, params.clone()),
        Err(RequestError::ClaimTxidMismatch)
    ));

    claim.output.truncate(1);
    assert!(matches!(
        AdminSigningRequest::new(claim.compute_txid(), &claim, params),
        Err(RequestError::MissingPayoutOutput)
    ));
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
        assert!(matches!(
            AdminSigningRequest::new(txid, &claim, mismatched),
            Err(RequestError::PayoutScriptMismatch)
        ));
    }
}

#[test]
fn rejects_an_unexpected_connector_amount() {
    let params = params();
    let mut claim = claim(&params);
    let expected = claim.output[1].value;
    claim.output[1].value += Amount::ONE_SAT;
    assert!(matches!(
        AdminSigningRequest::new(claim.compute_txid(), &claim, params),
        Err(RequestError::PayoutValueMismatch { expected: value, actual })
            if value == expected && actual == expected + Amount::ONE_SAT
    ));
}

#[tokio::test]
async fn signs_with_the_matching_admin_and_exports_the_sighash_byte() {
    let request = request();
    let signer = TestSigner::new(2);
    let signature = request.sign(&signer).await.unwrap();

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
    assert!(matches!(
        request().sign(&signer).await,
        Err(SigningError::UnauthorizedSigner(key)) if key == signer.public_key
    ));
    assert!(!signer.signing_called.load(Ordering::Relaxed));
}

#[tokio::test]
async fn rejects_a_backend_signature_from_a_different_key() {
    let mut signer = TestSigner::new(1);
    signer.signing_key = keypair(2);
    assert!(matches!(
        request().sign(&signer).await,
        Err(SigningError::InvalidSignature(_))
    ));
}

#[tokio::test]
async fn signature_cannot_authorize_a_different_claim() {
    let params = params();
    let mut claim = claim(&params);
    let first = AdminSigningRequest::new(claim.compute_txid(), &claim, params.clone()).unwrap();
    let signer = TestSigner::new(1);
    let signature = first.sign(&signer).await.unwrap();

    // Preserve the same payout connector while changing which claim creates it.
    claim.input[0].previous_output.vout += 1;
    let other = AdminSigningRequest::new(claim.compute_txid(), &claim, params).unwrap();
    assert_ne!(first.digest(), other.digest());
    assert!(SECP256K1
        .verify_schnorr(
            &signature.signature.signature,
            &Message::from_digest(other.digest()),
            &signer.public_key,
        )
        .is_err());
}
