#![expect(
    unused_crate_dependencies,
    reason = "the crate has dev-dependencies shared with other test targets"
)]
//! End-to-end compatibility proof for replacing Mosaic's toy verifier predicate with the real
//! SP1 Groth16 verifier.
//!
//! The test exercises the exact bridge-facing shape:
//! - 32 setup bytes (`program_id`),
//! - 4 deposit/public-value bytes,
//! - 128 compressed Groth16 proof bytes,
//! - 132 completed BIP340 signatures,
//! - conditional signing under the aggregate fault key when verification fails.
//!
//! This is a verifier-kernel and adaptor-flow proof of concept. It deliberately does not claim
//! that the BN254 verifier has already been compiled into RankVM tensor gates or that the
//! distributed garbling ceremony is production-ready.

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{AdditiveGroup, BigInteger, PrimeField};
use ark_secp256k1::{Fr, Projective};
use bitcoin::secp256k1::{
    Keypair, Message, SECP256K1, Scalar, SecretKey, XOnlyPublicKey,
    schnorr::Signature as BitcoinSignature,
};
use mosaic_adaptor_sigs::{Adaptor, Signature as CompletedAdaptorSignature, serialize_field};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES};
use zkaleido_sp1_groth16_verifier::{SP1Groth16Verifier, Sp1Groth16Proof};

const N_DEPOSIT_INPUTS: usize = 4;
const N_PROOF_INPUTS: usize = 128;
const N_SIGNED_INPUTS: usize = N_DEPOSIT_INPUTS + N_PROOF_INPUTS;

/// Real SP1 v6.1 Groth16 proof fixture from zkaleido.
///
/// Layout:
/// `vk_hash_tag || exit_code || vk_root || proof_nonce || uncompressed_groth16_proof`.
const FULL_SP1_PROOF_HEX: &str = concat!(
    "4388a21c0000000000000000000000000000000000000000000000000000000000000000002f850ee998974d6cc00e50",
    "cd0814b098c05bfade466d28573240d057f2535200000000000000000000000000000000000000000000000000000000",
    "0000000007229ae4bfd3adba05b9adc2e4ca4f672c6d55d93fd5f6d252658e791c2c598f0111bd8c1ae94557371b7ed6",
    "a5d7e134fd3563e9c8c5c2ec205e9559cea1ca9f2a249460c9a2e562f30d76edb44928565c1f5b07a7944985cf936acc",
    "4d763e1212e5c5635bdf65d714620991f77e6801ff36efb08d29d5aa31ab20f3ed668fac0404759fa720d9d8c1ad9dd3",
    "204301d182a6d0e2b467be3b5aa64ce3c3ca7c7e025ddfa505f3253771743a42ac0cd72d35b273e8807607178ad2a7ea",
    "833bfe43081c0362228bbb8f1881f37aea61e90d6277cf57d0761a91424fe86c61da78e72e931c418cd2c2f8710fa89e",
    "3e22e464f75f4a21d29091a021f92428c9f5090b",
);

const PROGRAM_ID_HEX: &str = "00de0b076134b5f87a6b27086d654ea12ea3465c09e092d93744ecc2a0efef4a";
const PUBLIC_VALUES: [u8; N_DEPOSIT_INPUTS] = [5, 0, 0, 0];

#[derive(Clone)]
struct CompletedInputs {
    adaptors: Vec<Adaptor>,
    signatures: Vec<CompletedAdaptorSignature>,
    sighashes: Vec<[u8; 32]>,
    evaluator_pubkey: Projective,
    evaluator_xonly: XOnlyPublicKey,
}

struct FaultLock {
    evaluator_share: SecretKey,
    garbler_share: SecretKey,
}

impl FaultLock {
    fn deterministic() -> Self {
        let mut evaluator = [0u8; 32];
        evaluator[31] = 2;
        let mut garbler = [0u8; 32];
        garbler[31] = 3;
        Self {
            evaluator_share: SecretKey::from_slice(&evaluator).expect("valid evaluator share"),
            garbler_share: SecretKey::from_slice(&garbler).expect("valid garbler share"),
        }
    }

    fn combined_secret(&self) -> SecretKey {
        let tweak =
            Scalar::from_be_bytes(self.garbler_share.secret_bytes()).expect("share is in range");
        self.evaluator_share
            .add_tweak(&tweak)
            .expect("non-zero aggregate fault secret")
    }

    fn public_key(&self) -> XOnlyPublicKey {
        Keypair::from_secret_key(SECP256K1, &self.combined_secret())
            .x_only_public_key()
            .0
    }

    fn sign(&self, digest: &[u8; 32]) -> BitcoinSignature {
        let keypair = Keypair::from_secret_key(SECP256K1, &self.combined_secret());
        let message = Message::from_digest_slice(digest).expect("32-byte digest");
        SECP256K1.sign_schnorr_no_aux_rand(&message, &keypair)
    }

    fn evaluator_only_signature(&self, digest: &[u8; 32]) -> BitcoinSignature {
        let keypair = Keypair::from_secret_key(SECP256K1, &self.evaluator_share);
        let message = Message::from_digest_slice(digest).expect("32-byte digest");
        SECP256K1.sign_schnorr_no_aux_rand(&message, &keypair)
    }

    fn garbler_only_signature(&self, digest: &[u8; 32]) -> BitcoinSignature {
        let keypair = Keypair::from_secret_key(SECP256K1, &self.garbler_share);
        let message = Message::from_digest_slice(digest).expect("32-byte digest");
        SECP256K1.sign_schnorr_no_aux_rand(&message, &keypair)
    }
}

struct RealSp1CompatibilityKernel {
    verifier: SP1Groth16Verifier,
    fault_lock: FaultLock,
}

impl RealSp1CompatibilityKernel {
    fn new(program_id: [u8; 32]) -> Self {
        let verifier =
            SP1Groth16Verifier::load(&GROTH16_VK_BYTES, program_id, *VK_ROOT_BYTES, true)
                .expect("real SP1 verifier must load");
        Self {
            verifier,
            fault_lock: FaultLock::deterministic(),
        }
    }

    fn evaluate_and_sign(
        &self,
        compressed_proof: &[u8; N_PROOF_INPUTS],
        public_values: &[u8],
        nack_digest: &[u8; 32],
    ) -> Option<BitcoinSignature> {
        self.verifier
            .verify(compressed_proof, public_values)
            .err()
            .map(|_| self.fault_lock.sign(nack_digest))
    }
}

fn fixture() -> ([u8; 32], [u8; N_PROOF_INPUTS]) {
    let program_id: [u8; 32] = hex::decode(PROGRAM_ID_HEX)
        .expect("program id hex")
        .try_into()
        .expect("32-byte program id");
    let full_proof = hex::decode(FULL_SP1_PROOF_HEX).expect("proof hex");
    let parsed = Sp1Groth16Proof::parse(&full_proof).expect("real proof parses");
    let compressed = parsed.proof.to_gnark_compressed_bytes();
    (program_id, compressed)
}

fn evaluator_keypair() -> (Fr, Projective, XOnlyPublicKey) {
    let mut secret = Fr::from(7u64);
    let mut public = Projective::generator() * secret;

    // Mosaic's adaptor implementation requires the canonical even-y BIP340 representative.
    if public.clone().into_affine().y.into_bigint().is_odd() {
        secret.neg_in_place();
        public.neg_in_place();
    }

    let bitcoin_secret =
        SecretKey::from_slice(&serialize_field(&secret)).expect("same secp256k1 scalar");
    let xonly = Keypair::from_secret_key(SECP256K1, &bitcoin_secret)
        .x_only_public_key()
        .0;
    (secret, public, xonly)
}

fn derive_share(wire: usize, value: u8) -> Fr {
    let mut hasher = Sha256::new();
    hasher.update(b"strata/rankvm-sp1-compat/share/v1");
    hasher.update((wire as u32).to_le_bytes());
    hasher.update([value]);
    let digest: [u8; 32] = hasher.finalize().into();
    let mut share = Fr::from_be_bytes_mod_order(&digest);
    if share == Fr::ZERO {
        share = Fr::from(1u64);
    }
    share
}

fn derive_sighash(wire: usize) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"strata/rankvm-sp1-compat/sighash/v1");
    hasher.update((wire as u32).to_le_bytes());
    hasher.finalize().into()
}

fn completed_signature_verifies(
    signature: &CompletedAdaptorSignature,
    sighash: &[u8; 32],
    evaluator_xonly: &XOnlyPublicKey,
) -> bool {
    let Ok(signature) = BitcoinSignature::from_slice(&signature.to_bytes()) else {
        return false;
    };
    let message = Message::from_digest_slice(sighash).expect("32-byte sighash");
    SECP256K1
        .verify_schnorr(&signature, &message, evaluator_xonly)
        .is_ok()
}

fn complete_inputs(
    public_values: [u8; N_DEPOSIT_INPUTS],
    compressed_proof: [u8; N_PROOF_INPUTS],
) -> CompletedInputs {
    let mut values = Vec::with_capacity(N_SIGNED_INPUTS);
    values.extend_from_slice(&public_values);
    values.extend_from_slice(&compressed_proof);
    assert_eq!(values.len(), N_SIGNED_INPUTS);

    let (evaluator_secret, evaluator_pubkey, evaluator_xonly) = evaluator_keypair();
    let mut rng = OsRng;
    let mut adaptors = Vec::with_capacity(N_SIGNED_INPUTS);
    let mut signatures = Vec::with_capacity(N_SIGNED_INPUTS);
    let mut sighashes = Vec::with_capacity(N_SIGNED_INPUTS);

    for (wire, value) in values.into_iter().enumerate() {
        let share = derive_share(wire, value);
        let commitment = Projective::generator() * share;
        let sighash = derive_sighash(wire);
        let adaptor = Adaptor::generate(
            &mut rng,
            commitment,
            evaluator_secret,
            evaluator_pubkey,
            &sighash,
        )
        .expect("adaptor generation");
        adaptor
            .verify(evaluator_pubkey, &sighash)
            .expect("adaptor verification");

        let signature = adaptor.complete(share);
        assert!(
            completed_signature_verifies(&signature, &sighash, &evaluator_xonly),
            "completed signature {wire} must be valid BIP340"
        );

        adaptors.push(adaptor);
        signatures.push(signature);
        sighashes.push(sighash);
    }

    CompletedInputs {
        adaptors,
        signatures,
        sighashes,
        evaluator_pubkey,
        evaluator_xonly,
    }
}

fn recover_selected_values(inputs: &CompletedInputs) -> Option<Vec<u8>> {
    let mut recovered = Vec::with_capacity(N_SIGNED_INPUTS);

    for wire in 0..N_SIGNED_INPUTS {
        if !completed_signature_verifies(
            &inputs.signatures[wire],
            &inputs.sighashes[wire],
            &inputs.evaluator_xonly,
        ) {
            return None;
        }
        inputs.adaptors[wire]
            .verify(inputs.evaluator_pubkey, &inputs.sighashes[wire])
            .ok()?;
        let extracted = inputs.adaptors[wire].extract_share(&inputs.signatures[wire]);
        let value = (0u16..=u8::MAX as u16)
            .map(|candidate| candidate as u8)
            .find(|candidate| derive_share(wire, *candidate) == extracted)?;
        recovered.push(value);
    }

    Some(recovered)
}

fn split_recovered(values: &[u8]) -> ([u8; N_DEPOSIT_INPUTS], [u8; N_PROOF_INPUTS]) {
    assert_eq!(values.len(), N_SIGNED_INPUTS);
    let public_values = values[..N_DEPOSIT_INPUTS]
        .try_into()
        .expect("4 public-value bytes");
    let proof = values[N_DEPOSIT_INPUTS..]
        .try_into()
        .expect("128 proof bytes");
    (public_values, proof)
}

#[test]
fn real_sp1_proof_drives_mosaic_compatible_fault_signing() {
    let (program_id, compressed_proof) = fixture();
    let kernel = RealSp1CompatibilityKernel::new(program_id);

    // First establish that this is the real SP1 Groth16 verification path, not the old toy
    // 71-AND predicate.
    assert!(
        kernel
            .verifier
            .verify(&compressed_proof, &PUBLIC_VALUES)
            .is_ok(),
        "real compressed SP1 proof must verify"
    );

    // Exercise Mosaic's exact 132-signature boundary and reconstruct all selected values from
    // completed adaptor signatures.
    let valid_inputs = complete_inputs(PUBLIC_VALUES, compressed_proof);
    assert_eq!(valid_inputs.signatures.len(), N_SIGNED_INPUTS);
    let recovered = recover_selected_values(&valid_inputs).expect("valid completed signatures");
    let (recovered_public_values, recovered_proof) = split_recovered(&recovered);
    assert_eq!(recovered_public_values, PUBLIC_VALUES);
    assert_eq!(recovered_proof, compressed_proof);

    let nack_digest: [u8; 32] = Sha256::digest(b"strata/rankvm-sp1-compat/nack/v1").into();

    // A valid counterproof must not unlock the fault key.
    assert!(
        kernel
            .evaluate_and_sign(&recovered_proof, &recovered_public_values, &nack_digest)
            .is_none()
    );

    // A malformed/invalid counterproof follows the same 132-signature path, but real Groth16
    // verification fails and conditionally releases a valid fault-key signature.
    let mut invalid_proof = compressed_proof;
    invalid_proof[N_PROOF_INPUTS - 1] ^= 1;
    assert!(
        kernel
            .verifier
            .verify(&invalid_proof, &PUBLIC_VALUES)
            .is_err()
    );
    let invalid_inputs = complete_inputs(PUBLIC_VALUES, invalid_proof);
    let recovered_invalid =
        recover_selected_values(&invalid_inputs).expect("well-formed signatures for invalid proof");
    let (invalid_public_values, recovered_invalid_proof) = split_recovered(&recovered_invalid);
    let fault_signature = kernel
        .evaluate_and_sign(
            &recovered_invalid_proof,
            &invalid_public_values,
            &nack_digest,
        )
        .expect("invalid proof must unlock fault signing");

    let nack_message = Message::from_digest_slice(&nack_digest).expect("32-byte digest");
    SECP256K1
        .verify_schnorr(
            &fault_signature,
            &nack_message,
            &kernel.fault_lock.public_key(),
        )
        .expect("aggregate fault signature verifies");

    // Neither setup share alone can impersonate the aggregate fault key.
    assert!(
        SECP256K1
            .verify_schnorr(
                &kernel.fault_lock.evaluator_only_signature(&nack_digest),
                &nack_message,
                &kernel.fault_lock.public_key(),
            )
            .is_err()
    );
    assert!(
        SECP256K1
            .verify_schnorr(
                &kernel.fault_lock.garbler_only_signature(&nack_digest),
                &nack_message,
                &kernel.fault_lock.public_key(),
            )
            .is_err()
    );

    // Corrupting a completed adaptor signature is detected before verifier evaluation.
    let mut tampered = valid_inputs.clone();
    tampered.signatures[0].s += Fr::from(1u64);
    assert!(recover_selected_values(&tampered).is_none());

    eprintln!(
        "rankvm-sp1-compat: real SP1 proof verified; {} adaptor signatures round-tripped; invalid proof unlocked aggregate fault signing",
        N_SIGNED_INPUTS
    );
}
