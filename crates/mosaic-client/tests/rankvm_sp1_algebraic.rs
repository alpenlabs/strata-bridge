#![expect(
    unused_crate_dependencies,
    reason = "the crate has dev-dependencies shared with other test targets"
)]
//! Differential test for the high-level algebraic kernel that a RankVM compiler must implement.
//!
//! This independently parses the verifier and proof from their public byte encodings, rebuilds the
//! dynamic G1 MSM, and evaluates the four-term BN254 pairing-product equation. It intentionally uses
//! native `substrate-bn` group operations for now: this isolates the exact semantic target for the
//! future `LIN/TENSOR` backend without pretending the pairings are already garbled.

use bn::{AffineG1, AffineG2, Fq, Fq2, Fr, G1, G2, Group, Gt, pairing_batch};
use sha2::{Digest, Sha256};
use sp1_verifier::{GROTH16_VK_BYTES, VK_ROOT_BYTES};
use zkaleido_sp1_groth16_verifier::{SP1Groth16Verifier, Sp1Groth16Proof};

const FQ_BYTES: usize = 32;
const G1_BYTES: usize = 64;
const G2_BYTES: usize = 128;
const PROOF_BYTES: usize = 256;
const VERIFIER_HEADER_BYTES: usize = 4 + 32 + 1;
const VK_FIXED_BYTES: usize = G1_BYTES + 3 * G2_BYTES + 4;

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
const PUBLIC_VALUES: [u8; 4] = [5, 0, 0, 0];

#[derive(Debug)]
struct AlgebraicVk {
    alpha: AffineG1,
    beta: AffineG2,
    gamma: AffineG2,
    delta: AffineG2,
    k: Vec<AffineG1>,
}

#[derive(Debug)]
struct AlgebraicProof {
    a: AffineG1,
    b: AffineG2,
    c: AffineG1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KernelTrace {
    dynamic_public_scalars: usize,
    nonzero_msm_terms: usize,
    pairing_terms: usize,
}

#[derive(Debug)]
struct RankVmSp1AlgebraicKernel {
    vk: AlgebraicVk,
    pinned_vk_root: [u8; 32],
}

impl RankVmSp1AlgebraicKernel {
    fn from_native(verifier: &SP1Groth16Verifier) -> Self {
        let serialized = verifier.to_uncompressed_bytes();
        let vk_bytes = serialized
            .get(VERIFIER_HEADER_BYTES..)
            .expect("serialized verifier header");
        assert!(vk_bytes.len() >= VK_FIXED_BYTES);

        let alpha = parse_g1(&vk_bytes[..G1_BYTES]);
        let beta = parse_g2(&vk_bytes[G1_BYTES..G1_BYTES + G2_BYTES]);
        let gamma = parse_g2(&vk_bytes[G1_BYTES + G2_BYTES..G1_BYTES + 2 * G2_BYTES]);
        let delta = parse_g2(&vk_bytes[G1_BYTES + 2 * G2_BYTES..G1_BYTES + 3 * G2_BYTES]);

        let num_k_offset = G1_BYTES + 3 * G2_BYTES;
        let num_k = u32::from_be_bytes(
            vk_bytes[num_k_offset..num_k_offset + 4]
                .try_into()
                .expect("num_k bytes"),
        ) as usize;
        let mut offset = num_k_offset + 4;
        let mut k = Vec::with_capacity(num_k);
        for _ in 0..num_k {
            k.push(parse_g1(&vk_bytes[offset..offset + G1_BYTES]));
            offset += G1_BYTES;
        }
        assert_eq!(offset, vk_bytes.len(), "unexpected verifier tail");

        Self {
            vk: AlgebraicVk {
                alpha,
                beta,
                gamma,
                delta,
                k,
            },
            pinned_vk_root: verifier.vk_root,
        }
    }

    fn public_inputs(&self, proof: &Sp1Groth16Proof, public_values: &[u8]) -> [Fr; 4] {
        let exit_code = proof.exit_code.unwrap_or([0u8; 32]);
        let vk_root = proof.vk_root.unwrap_or(self.pinned_vk_root);
        let proof_nonce = proof.proof_nonce.unwrap_or([0u8; 32]);
        [
            hash_public_values(public_values),
            parse_fr(&exit_code),
            parse_fr(&vk_root),
            parse_fr(&proof_nonce),
        ]
    }

    fn verify(
        &self,
        proof_bytes: &[u8; PROOF_BYTES],
        public_inputs: &[Fr; 4],
    ) -> (bool, KernelTrace) {
        assert_eq!(self.vk.k.len(), public_inputs.len() + 1);
        let proof = parse_proof(proof_bytes);

        let mut prepared_input = Into::<G1>::into(self.vk.k[0]);
        let mut nonzero_msm_terms = 0usize;
        for (input, k) in public_inputs.iter().zip(self.vk.k.iter().skip(1)) {
            if *input != Fr::zero() {
                prepared_input = prepared_input + Into::<G1>::into(*k) * *input;
                nonzero_msm_terms += 1;
            }
        }

        let pairing_result = pairing_batch(&[
            (-Into::<G1>::into(proof.a), Into::<G2>::into(proof.b)),
            (prepared_input, Into::<G2>::into(self.vk.gamma)),
            (Into::<G1>::into(proof.c), Into::<G2>::into(self.vk.delta)),
            (Into::<G1>::into(self.vk.alpha), Into::<G2>::into(self.vk.beta)),
        ]);

        (
            pairing_result == Gt::one(),
            KernelTrace {
                dynamic_public_scalars: public_inputs.len(),
                nonzero_msm_terms,
                pairing_terms: 4,
            },
        )
    }
}

fn parse_fq(bytes: &[u8]) -> Fq {
    Fq::from_slice(bytes).expect("canonical BN254 base-field element")
}

fn parse_fr(bytes: &[u8]) -> Fr {
    Fr::from_slice(bytes).expect("canonical BN254 scalar-field element")
}

fn parse_g1(bytes: &[u8]) -> AffineG1 {
    assert_eq!(bytes.len(), G1_BYTES);
    AffineG1::new(parse_fq(&bytes[..FQ_BYTES]), parse_fq(&bytes[FQ_BYTES..]))
        .expect("valid G1 point")
}

fn parse_g2(bytes: &[u8]) -> AffineG2 {
    assert_eq!(bytes.len(), G2_BYTES);
    let x1 = parse_fq(&bytes[..FQ_BYTES]);
    let x0 = parse_fq(&bytes[FQ_BYTES..2 * FQ_BYTES]);
    let y1 = parse_fq(&bytes[2 * FQ_BYTES..3 * FQ_BYTES]);
    let y0 = parse_fq(&bytes[3 * FQ_BYTES..]);
    AffineG2::new(Fq2::new(x0, x1), Fq2::new(y0, y1)).expect("valid G2 point")
}

fn parse_proof(bytes: &[u8; PROOF_BYTES]) -> AlgebraicProof {
    AlgebraicProof {
        a: parse_g1(&bytes[..G1_BYTES]),
        b: parse_g2(&bytes[G1_BYTES..G1_BYTES + G2_BYTES]),
        c: parse_g1(&bytes[G1_BYTES + G2_BYTES..]),
    }
}

fn hash_public_values(public_values: &[u8]) -> Fr {
    let mut digest: [u8; 32] = Sha256::digest(public_values).into();
    digest[0] &= 0x1f;
    parse_fr(&digest)
}

fn fixture() -> ([u8; 32], Vec<u8>, Sp1Groth16Proof) {
    let program_id = hex::decode(PROGRAM_ID_HEX)
        .expect("program id hex")
        .try_into()
        .expect("32-byte program id");
    let full_proof = hex::decode(FULL_SP1_PROOF_HEX).expect("proof hex");
    let parsed = Sp1Groth16Proof::parse(&full_proof).expect("real proof parses");
    (program_id, full_proof, parsed)
}

#[test]
fn extracted_algebraic_kernel_matches_native_sp1_verifier() {
    let (program_id, full_proof, parsed) = fixture();
    let native = SP1Groth16Verifier::load(&GROTH16_VK_BYTES, program_id, *VK_ROOT_BYTES, true)
        .expect("native verifier loads");
    assert!(native.verify(&full_proof, &PUBLIC_VALUES).is_ok());

    let kernel = RankVmSp1AlgebraicKernel::from_native(&native);
    let proof_uncompressed = parsed.proof.to_uncompressed_bytes();
    let public_inputs = kernel.public_inputs(&parsed, &PUBLIC_VALUES);
    let (valid, trace) = kernel.verify(&proof_uncompressed, &public_inputs);
    assert!(valid, "extracted algebraic kernel must accept the real proof");
    assert_eq!(trace.dynamic_public_scalars, 4);
    assert_eq!(trace.pairing_terms, 4);

    // Swap the two valid G1 proof points. The bytes remain parseable curve points, but the
    // Groth16 equation must fail in both the native verifier and the extracted kernel.
    let mut invalid_proof = proof_uncompressed;
    let a: [u8; G1_BYTES] = invalid_proof[..G1_BYTES]
        .try_into()
        .expect("A bytes");
    let c: [u8; G1_BYTES] = invalid_proof[G1_BYTES + G2_BYTES..]
        .try_into()
        .expect("C bytes");
    invalid_proof[..G1_BYTES].copy_from_slice(&c);
    invalid_proof[G1_BYTES + G2_BYTES..].copy_from_slice(&a);

    let invalid_parsed = Sp1Groth16Proof::parse(&invalid_proof).expect("swapped proof parses");
    let invalid_inputs = kernel.public_inputs(&invalid_parsed, &PUBLIC_VALUES);
    let native_accepts_invalid = native.verify(&invalid_proof, &PUBLIC_VALUES).is_ok();
    let (kernel_accepts_invalid, invalid_trace) = kernel.verify(&invalid_proof, &invalid_inputs);
    assert_eq!(kernel_accepts_invalid, native_accepts_invalid);
    assert!(!kernel_accepts_invalid, "swapped proof must be rejected");
    assert_eq!(invalid_trace.pairing_terms, 4);

    eprintln!(
        "rankvm-sp1-algebraic: native and extracted kernels agree; {} dynamic scalars ({} non-zero for fixture), {} pairing terms",
        trace.dynamic_public_scalars, trace.nonzero_msm_terms, trace.pairing_terms
    );
}
