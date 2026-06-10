#![expect(
    unused_crate_dependencies,
    reason = "this integration-test binary doesn't reference every dependency declared in Cargo.toml"
)]
//! Round-trips a Groth16-wrapped SP1 proof through the mosaic adaptor-signature
//! encoding used by the counterproof transaction, and checks that the proof
//! recovered from the completed signatures still verifies against the Groth16
//! verifying key and the program's public values.
//!
//! Pipeline under test (mirrors production):
//!
//! 1. Watchtower side (`generate_counterproof` in `src/graph/counterproof.rs`): SP1 receipt ->
//!    `Sp1Groth16Proof::parse` -> `to_gnark_compressed_bytes()` -> 128-byte `G16ProofRaw`. This
//!    strips the SP1 prefix fields (vk hash tag, exit code, vk root, proof nonce); only the bare
//!    gnark-compressed proof goes on chain.
//! 2. Mosaic deposit init (evaluator side): one adaptor pre-signature per (wire, byte value) — 256
//!    per withdrawal wire — each committing to the garbler's share `S = share·G` for that value
//!    (mosaic `evaluator.rs`).
//! 3. Mosaic contested withdrawal (garbler side, `complete_adaptor_sigs`): per wire `i`, complete
//!    adaptor `[i][proof[i]]` with the matching share, yielding the BIP340-valid signatures that
//!    are published in the counterproof tx witness (mosaic `garbler.rs`).
//! 4. Evaluator decode (mirrors mosaic's `extract_withdrawal_input_from_signatures` in
//!    `cac/protocol/src/evaluator/stf.rs`): per wire, extract the candidate share with each of the
//!    256 adaptors and find the unique value whose share matches the commitment.
//! 5. Verify the recovered 128 bytes against the Groth16 vkey + the program's public values.
//!
//! The fixture is the SP1 v6.1.0 fibonacci Groth16 receipt that zkaleido's own
//! verifier tests use (same zkaleido tag as this workspace pins). The counterproof
//! program produces receipts of the same shape; for it, `public_values` is the
//! SSZ-encoded `CounterproofOutput { operator_pubkey, game_idx }`, which a verifier
//! reconstructs from the public game parameters.

use std::path::Path;

use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use bitcoin::{
    hashes::{Hash, sha256},
    secp256k1::{Message, Secp256k1, XOnlyPublicKey, schnorr},
};
use mosaic_adaptor_sigs::{Adaptor, Signature as AdaptorSignature, serialize_field};
use rand::{SeedableRng, rngs::StdRng};
use sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES};
use strata_mosaic_client_api::types::N_WITHDRAWAL_INPUT_WIRES;
use zkaleido::ProofReceiptWithMetadata;
use zkaleido_sp1_groth16_verifier::{SP1Groth16Verifier, Sp1Groth16Proof};

type Fr = ark_secp256k1::Fr;
type Projective = ark_secp256k1::Projective;

/// One adaptor per possible byte value per wire, as in mosaic
/// (`WIDE_LABEL_VALUE_COUNT`).
const N_VALUES: usize = 256;

/// Everything both parties hold for a single withdrawal wire (= one proof byte).
struct Wire {
    /// The per-wire sighash. On chain each wire gets a unique sighash via the
    /// `OP_CODESEPARATOR` chain in the `ContestCounterproofOutput` leaf script.
    sighash: [u8; 32],
    /// Garbler-side secrets, indexed by byte value.
    shares: Vec<Fr>,
    /// `S = share·G`, known to both sides, indexed by byte value. Stands in for
    /// the VSSS polynomial zeroth-coefficient commitments.
    commitments: Vec<Projective>,
    /// Evaluator pre-signatures, indexed by byte value.
    adaptors: Vec<Adaptor>,
}

/// Loads the SP1 Groth16 receipt fixture.
fn load_receipt() -> ProofReceiptWithMetadata {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/fibonacci_SP1_v6.1.0.proof.bin");
    ProofReceiptWithMetadata::load(path).expect("fixture receipt must load")
}

/// Gnark-compresses the receipt's proof to the on-chain `G16ProofRaw` form,
/// exactly as `generate_counterproof` does.
fn gnark_compress(receipt: &ProofReceiptWithMetadata) -> [u8; N_WITHDRAWAL_INPUT_WIRES] {
    let parsed = Sp1Groth16Proof::parse(receipt.receipt().proof().as_bytes())
        .expect("fixture proof must parse");
    parsed.proof.to_gnark_compressed_bytes()
}

/// Builds the verifier the same way `sp1_groth16_predicate_key` does.
fn build_verifier(receipt: &ProofReceiptWithMetadata) -> SP1Groth16Verifier {
    SP1Groth16Verifier::load(
        &GROTH16_VK_BYTES,
        receipt.metadata().program_id().0,
        *VK_ROOT_BYTES,
        true,
    )
    .expect("verifier must load")
}

/// Evaluator master keypair with the even-y public key that
/// [`Adaptor::generate`] requires (BIP340 canonical form).
fn even_y_keypair(rng: &mut StdRng) -> (Fr, Projective) {
    let mut sk = Fr::rand(rng);
    let mut pk = Projective::generator() * sk;
    if pk.into_affine().y.into_bigint().is_odd() {
        sk = -sk;
        pk = -pk;
    }
    (sk, pk)
}

/// Deposit-init phase: the evaluator generates one adaptor per (wire, value).
fn setup_wires(rng: &mut StdRng, sk: Fr, pk: Projective, n_wires: usize) -> Vec<Wire> {
    (0..n_wires)
        .map(|wire_idx| {
            let sighash = sha256::Hash::hash(format!("counterproof-wire-{wire_idx}").as_bytes())
                .to_byte_array();
            let shares: Vec<Fr> = (0..N_VALUES).map(|_| Fr::rand(rng)).collect();
            let commitments: Vec<Projective> =
                shares.iter().map(|s| Projective::generator() * s).collect();
            let adaptors: Vec<Adaptor> = commitments
                .iter()
                .map(|commitment| {
                    Adaptor::generate(rng, *commitment, sk, pk, &sighash)
                        .expect("adaptor generation must succeed")
                })
                .collect();
            Wire {
                sighash,
                shares,
                commitments,
                adaptors,
            }
        })
        .collect()
}

/// Garbler side of `complete_adaptor_sigs`: pick the adaptor indexed by the
/// proof byte and complete it with the matching share.
fn complete_signatures(wires: &[Wire], proof_bytes: &[u8]) -> Vec<AdaptorSignature> {
    wires
        .iter()
        .zip(proof_bytes)
        .map(|(wire, &byte)| {
            let val = byte as usize;
            wire.adaptors[val].complete(wire.shares[val])
        })
        .collect()
}

/// Evaluator decode of one wire, mirroring mosaic's
/// `extract_withdrawal_input_from_signatures`: try every value's adaptor and
/// return the one whose extracted share matches the commitment.
fn decode_wire(wire: &Wire, sig: &AdaptorSignature) -> Option<u8> {
    (0..N_VALUES).find_map(|val| {
        let candidate = wire.adaptors[val].extract_share(sig);
        (Projective::generator() * candidate == wire.commitments[val]).then_some(val as u8)
    })
}

/// BIP340-verifies a completed adaptor signature the way Bitcoin consensus
/// does for each `OP_CHECKSIGVERIFY` in the counterproof leaf script.
fn consensus_verify(sig: &AdaptorSignature, pk: &Projective, sighash: &[u8; 32]) -> bool {
    let secp = Secp256k1::verification_only();
    let xonly = XOnlyPublicKey::from_slice(&serialize_field(&pk.into_affine().x))
        .expect("even-y pk x-coordinate is a valid x-only key");
    let Ok(schnorr_sig) = schnorr::Signature::from_slice(&sig.to_bytes()) else {
        return false;
    };
    let msg = Message::from_digest(*sighash);
    secp.verify_schnorr(&schnorr_sig, &msg, &xonly).is_ok()
}

/// The test the whole file is about: compress the proof, post it as completed
/// adaptor signatures, recover it from those signatures, and check that the
/// recovered bytes still verify against the vkey + public values.
#[test]
fn recovered_counterproof_verifies_against_vkey() {
    let receipt = load_receipt();
    let raw = gnark_compress(&receipt);
    let verifier = build_verifier(&receipt);
    let public_values = receipt.receipt().public_values().as_bytes();

    // Sanity: the freshly compressed proof verifies before any adaptor work,
    // isolating compression failures from recovery failures.
    verifier
        .verify(&raw, public_values)
        .expect("gnark-compressed proof must verify pre-roundtrip");

    // Deposit init: evaluator generates 256 adaptors per wire.
    let mut rng = StdRng::seed_from_u64(0x5742_4c41);
    let (sk, pk) = even_y_keypair(&mut rng);
    let wires = setup_wires(&mut rng, sk, pk, N_WITHDRAWAL_INPUT_WIRES);

    // Garbler-side adaptor verification (the `AdaptorsVerified` step). Spot-check
    // one wire; mosaic verifies all 128 x 256 at deposit time.
    for adaptor in &wires[0].adaptors {
        adaptor
            .verify(pk, &wires[0].sighash)
            .expect("well-formed adaptor must verify");
    }

    // Contested withdrawal: garbler completes one adaptor per wire, selected
    // by the proof byte.
    let signatures = complete_signatures(&wires, &raw);

    // Every published signature must pass BIP340 — this is what Bitcoin
    // consensus enforces, and what pins each signature to exactly one
    // committed (wire, value) share.
    for (wire, sig) in wires.iter().zip(&signatures) {
        assert!(
            consensus_verify(sig, &pk, &wire.sighash),
            "completed adaptor signature must be consensus-valid",
        );
    }

    // Evaluator decode: recover the proof bytes from the signatures alone.
    let recovered: Vec<u8> = wires
        .iter()
        .zip(&signatures)
        .map(|(wire, sig)| decode_wire(wire, sig).expect("each wire must decode to a unique byte"))
        .collect();

    // The recovered bytes are exactly the posted proof...
    assert_eq!(recovered, raw, "adaptor recovery must be byte-exact");

    // ...and still verify as a Groth16 proof against the vkey and the public
    // values reconstructed by the verifier.
    verifier
        .verify(&recovered, public_values)
        .expect("recovered proof must verify against vkey + public values");
}

/// A single flipped byte in the recovered proof must fail verification: byte
/// equality is what carries proof validity through the round trip.
#[test]
fn tampered_recovered_proof_fails_verification() {
    let receipt = load_receipt();
    let mut raw = gnark_compress(&receipt);
    let verifier = build_verifier(&receipt);

    raw[17] ^= 0x01;

    assert!(
        verifier
            .verify(&raw, receipt.receipt().public_values().as_bytes())
            .is_err(),
        "a proof differing in one byte must not verify",
    );
}

/// A garbler that completes a wire's adaptor with the share of a *different*
/// byte value produces a signature that (a) fails BIP340 — Bitcoin consensus
/// would reject the counterproof tx — and (b) matches no committed value on
/// decode. Equivocating between the posted proof and the decoded proof is
/// therefore impossible.
#[test]
fn wrong_share_completion_fails_consensus_and_decode() {
    let mut rng = StdRng::seed_from_u64(0x6661_554c);
    let (sk, pk) = even_y_keypair(&mut rng);
    let wires = setup_wires(&mut rng, sk, pk, 1);
    let wire = &wires[0];

    let (claimed_val, actual_val) = (0xab_usize, 0xcd_usize);
    let forged = wire.adaptors[claimed_val].complete(wire.shares[actual_val]);

    assert!(
        !consensus_verify(&forged, &pk, &wire.sighash),
        "completing with a mismatched share must break the schnorr signature",
    );
    assert_eq!(
        decode_wire(wire, &forged),
        None,
        "a forged signature must not decode to any committed byte value",
    );
}
