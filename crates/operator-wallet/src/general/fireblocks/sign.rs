//! Witness assembly from Fireblocks ECDSA signatures.
//!
//! Fireblocks returns a raw `r || s` ECDSA signature (`fullSig`, 64 bytes hex) plus the
//! signing public key for each message. For a P2WPKH input the witness is
//! `[DER(sig) || SIGHASH_ALL, compressed_pubkey]`, so this converts the compact signature to
//! DER, low-S-normalises it (Bitcoin consensus requires low-S), appends the sighash-type byte,
//! and pairs it with the pubkey.
//!
//! Crucially it also performs two checks against the untrusted RAW-signing response before
//! trusting the witness — RAW signing lets Fireblocks choose the signing key and returns a bare
//! `r||s`, so a wrong key or a signature that doesn't match the sighash would otherwise yield a
//! structurally valid but invalid witness that only fails at broadcast:
//! 1. the returned pubkey actually controls the input — `hash160(pubkey)` must equal the input's
//!    P2WPKH witness program; and
//! 2. the signature actually verifies against the `sighash` we asked Fireblocks to sign.

use bdk_wallet::bitcoin::{
    ecdsa,
    secp256k1::{self, ecdsa::Signature as SecpSignature, Message, Secp256k1},
    CompressedPublicKey, EcdsaSighashType, Script, ScriptBuf, Witness,
};

use super::FireblocksError;

/// Builds the P2WPKH witness for one input from Fireblocks' `fullSig` (hex `r||s`), the signing
/// public key (hex, compressed), and the `sighash` that was sent for signing. Low-S-normalises
/// the signature before DER-encoding, checks the pubkey hashes to `expected_script`'s witness
/// program, and verifies the signature against `sighash` under that pubkey.
pub(super) fn assemble_p2wpkh_witness(
    full_sig_hex: &str,
    public_key_hex: &str,
    expected_script: &Script,
    sighash: &[u8; 32],
) -> Result<Witness, FireblocksError> {
    let sig_bytes = hex::decode(full_sig_hex)
        .map_err(|e| FireblocksError::Witness(format!("signature hex: {e}")))?;
    let mut signature = SecpSignature::from_compact(&sig_bytes)
        .map_err(|e| FireblocksError::Witness(format!("compact signature: {e}")))?;
    // Bitcoin requires low-S; Fireblocks usually returns low-S already, but normalise to be safe.
    signature.normalize_s();

    let ecdsa_sig = ecdsa::Signature {
        signature,
        sighash_type: EcdsaSighashType::All,
    };

    let pubkey_bytes = hex::decode(public_key_hex)
        .map_err(|e| FireblocksError::Witness(format!("pubkey hex: {e}")))?;
    // Validate it parses as a public key so we fail here rather than at broadcast.
    let pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| FireblocksError::Witness(format!("pubkey: {e}")))?;
    let compressed = CompressedPublicKey::from_slice(&pubkey_bytes)
        .map_err(|e| FireblocksError::Witness(format!("compressed pubkey: {e}")))?;

    // The signing key must actually control this input: its P2WPKH script must match the
    // prevout we're spending. Guards against Fireblocks signing with the wrong vault key.
    let derived_script = ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash());
    if derived_script != *expected_script {
        return Err(FireblocksError::Witness(format!(
            "signing pubkey does not control the input: derived script {derived_script:?} != prevout script {expected_script:?}"
        )));
    }

    // The signature must actually verify against the sighash we asked Fireblocks to sign — catch a
    // bad/garbled `fullSig` here rather than letting an invalid witness fail at broadcast. ECDSA
    // verification is malleability-agnostic, so the low-S-normalised signature still verifies.
    Secp256k1::verification_only()
        .verify_ecdsa(&Message::from_digest(*sighash), &signature, &pubkey)
        .map_err(|e| {
            FireblocksError::Witness(format!(
                "signature does not verify against the sighash: {e}"
            ))
        })?;

    let mut witness = Witness::new();
    witness.push(ecdsa_sig.to_vec());
    witness.push(&pubkey_bytes);
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    use super::*;

    /// Returns a real signature, the compressed pubkey hex, the P2WPKH script the pubkey
    /// controls, and the signed sighash — so the happy-path test feeds a matching
    /// `expected_script` and the signature verifies.
    fn sig_pubkey_script(sk_byte: u8, msg_byte: u8) -> (String, String, ScriptBuf, [u8; 32]) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[sk_byte; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let sighash = [msg_byte; 32];
        let sig = secp.sign_ecdsa(&Message::from_digest(sighash), &sk);
        let compressed = CompressedPublicKey(pk);
        let script = ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash());
        (
            hex::encode(sig.serialize_compact()),
            hex::encode(pk.serialize()),
            script,
            sighash,
        )
    }

    #[test]
    fn assembles_witness_with_der_sig_and_pubkey() {
        let (full_sig_hex, pubkey_hex, script, sighash) = sig_pubkey_script(0x11, 0x22);
        let witness = assemble_p2wpkh_witness(&full_sig_hex, &pubkey_hex, &script, &sighash)
            .expect("assembles");
        let items: Vec<&[u8]> = witness.iter().collect();
        assert_eq!(items.len(), 2, "P2WPKH witness has 2 items");
        // Item 0: DER signature ending in the SIGHASH_ALL byte; item 1: the 33-byte pubkey.
        assert_eq!(*items[0].last().unwrap(), EcdsaSighashType::All as u8);
        assert_eq!(items[0][0], 0x30, "DER sequence tag");
        assert_eq!(items[1].len(), 33);
    }

    #[test]
    fn rejects_pubkey_that_does_not_control_the_input() {
        let (full_sig_hex, pubkey_hex, _script, sighash) = sig_pubkey_script(0x11, 0x22);
        // A script for a *different* key — the returned pubkey must not satisfy it.
        let (_, _, other_script, _) = sig_pubkey_script(0x99, 0x22);
        let err = assemble_p2wpkh_witness(&full_sig_hex, &pubkey_hex, &other_script, &sighash)
            .unwrap_err();
        assert!(matches!(err, FireblocksError::Witness(_)));
    }

    #[test]
    fn rejects_signature_that_does_not_verify_against_the_sighash() {
        // Correct key + controlling script, but a sighash the signature was not made for.
        let (full_sig_hex, pubkey_hex, script, _) = sig_pubkey_script(0x11, 0x22);
        let wrong_sighash = [0x77u8; 32];
        let err = assemble_p2wpkh_witness(&full_sig_hex, &pubkey_hex, &script, &wrong_sighash)
            .unwrap_err();
        assert!(matches!(err, FireblocksError::Witness(_)));
    }

    #[test]
    fn rejects_malformed_signature_hex() {
        let (_, _, script, sighash) = sig_pubkey_script(0x11, 0x22);
        assert!(assemble_p2wpkh_witness("not-hex", "00", &script, &sighash).is_err());
        // Right hex, wrong length for a compact signature.
        assert!(assemble_p2wpkh_witness("aabb", "00", &script, &sighash).is_err());
    }

    #[test]
    fn rejects_bad_pubkey() {
        let (full_sig_hex, _, script, sighash) = sig_pubkey_script(0x33, 0x44);
        assert!(assemble_p2wpkh_witness(&full_sig_hex, "deadbeef", &script, &sighash).is_err());
    }

    /// A high-S compact signature must be normalized to low-S before DER-encoding (Bitcoin
    /// consensus rejects high-S). `sign_ecdsa` always returns low-S, so flip it to its high-S
    /// counterpart `(r, n - s)`, feed that through, and confirm the assembled DER signature
    /// carries the original low-S `s`.
    #[test]
    fn normalizes_high_s_signature() {
        // secp256k1 group order n, big-endian.
        const N: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFE, 0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C,
            0xD0, 0x36, 0x41, 0x41,
        ];

        /// Big-endian `a - b` for 32-byte values, assuming `a >= b`.
        fn sub_be(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
            let mut out = [0u8; 32];
            let mut borrow = 0i16;
            for i in (0..32).rev() {
                let diff = a[i] as i16 - b[i] as i16 - borrow;
                if diff < 0 {
                    out[i] = (diff + 256) as u8;
                    borrow = 1;
                } else {
                    out[i] = diff as u8;
                    borrow = 0;
                }
            }
            out
        }

        let (low_s_hex, pubkey_hex, script, sighash) = sig_pubkey_script(0x55, 0x66);
        let low_compact: [u8; 32 * 2] = hex::decode(&low_s_hex).unwrap().try_into().unwrap();
        let low_s: [u8; 32] = low_compact[32..].try_into().unwrap();

        // High-S form: r unchanged, s -> n - s.
        let high_s = sub_be(&N, &low_s);
        let mut high_compact = low_compact;
        high_compact[32..].copy_from_slice(&high_s);

        let witness =
            assemble_p2wpkh_witness(&hex::encode(high_compact), &pubkey_hex, &script, &sighash)
                .expect("assembles even when handed a high-S signature");
        let items: Vec<&[u8]> = witness.iter().collect();
        let der = &items[0][..items[0].len() - 1];
        let assembled_s = SecpSignature::from_der(der)
            .expect("der")
            .serialize_compact()[32..]
            .to_vec();
        assert_eq!(
            assembled_s, low_s,
            "high-S input must be normalized back to the low-S form"
        );
    }

    /// End-to-end: sign a real BIP-143 sighash for a P2WPKH spend (standing in for Fireblocks),
    /// assemble the witness, and confirm the DER signature it carries verifies against that
    /// sighash under the signing key. This pins the load-bearing property of RAW signing — that
    /// the assembled witness is actually valid for the transaction being spent.
    #[test]
    fn assembled_witness_signature_verifies_against_the_sighash() {
        use bdk_wallet::bitcoin::{
            absolute::LockTime, transaction::Version, Amount, OutPoint, Sequence, Transaction,
            TxIn, TxOut,
        };

        use crate::general::fireblocks::tx;

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let compressed = CompressedPublicKey(pk);
        let spk = ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash());

        let prevout = TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: spk.clone(),
        };
        let spending_tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(90_000),
                script_pubkey: spk.clone(),
            }],
        };

        let sighash = tx::p2wpkh_sighash(&spending_tx, 0, &[prevout]).expect("sighash");
        let msg = Message::from_digest(sighash);
        let sig = secp.sign_ecdsa(&msg, &sk);

        let witness = assemble_p2wpkh_witness(
            &hex::encode(sig.serialize_compact()),
            &hex::encode(pk.serialize()),
            &spk,
            &sighash,
        )
        .expect("assembles");

        // Drop the trailing SIGHASH_ALL byte, parse the DER signature, and verify it against the
        // sighash under the signing pubkey.
        let items: Vec<&[u8]> = witness.iter().collect();
        let der = &items[0][..items[0].len() - 1];
        let parsed = SecpSignature::from_der(der).expect("der signature");
        secp.verify_ecdsa(&msg, &parsed, &pk)
            .expect("witness signature verifies against the sighash");
    }
}
