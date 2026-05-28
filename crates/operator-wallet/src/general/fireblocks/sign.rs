//! Witness assembly from Fireblocks ECDSA signatures.
//!
//! Fireblocks returns a raw `r || s` ECDSA signature (`fullSig`, 64 bytes hex) plus the
//! signing public key for each message. For a P2WPKH input the witness is
//! `[DER(sig) || SIGHASH_ALL, compressed_pubkey]`, so this converts the compact signature to
//! DER, low-S-normalises it (Bitcoin consensus requires low-S), appends the sighash-type byte,
//! and pairs it with the pubkey.
//!
//! Crucially it also verifies the returned pubkey actually controls the input being spent —
//! `hash160(pubkey)` must equal the input's P2WPKH witness program. RAW signing lets Fireblocks
//! choose the signing key, so without this check a key mismatch (e.g. a rotated/derived address)
//! would produce a structurally valid but unspendable witness that only fails at broadcast.

use bdk_wallet::bitcoin::{
    ecdsa,
    secp256k1::{self, ecdsa::Signature as SecpSignature},
    CompressedPublicKey, EcdsaSighashType, Script, ScriptBuf, Witness,
};

use super::FireblocksError;

/// Builds the P2WPKH witness for one input from Fireblocks' `fullSig` (hex `r||s`) and the
/// signing public key (hex, compressed), checking that the pubkey hashes to
/// `expected_script`'s witness program. Low-S-normalises the signature before DER-encoding.
pub(super) fn assemble_p2wpkh_witness(
    full_sig_hex: &str,
    public_key_hex: &str,
    expected_script: &Script,
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
    secp256k1::PublicKey::from_slice(&pubkey_bytes)
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

    let mut witness = Witness::new();
    witness.push(ecdsa_sig.to_vec());
    witness.push(&pubkey_bytes);
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    use super::*;

    /// Returns a real signature, the compressed pubkey hex, and the P2WPKH script the pubkey
    /// controls — so the happy-path test feeds a matching `expected_script`.
    fn sig_pubkey_script(sk_byte: u8, msg_byte: u8) -> (String, String, ScriptBuf) {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[sk_byte; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let msg = Message::from_digest([msg_byte; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);
        let compressed = CompressedPublicKey(pk);
        let script = ScriptBuf::new_p2wpkh(&compressed.wpubkey_hash());
        (
            hex::encode(sig.serialize_compact()),
            hex::encode(pk.serialize()),
            script,
        )
    }

    #[test]
    fn assembles_witness_with_der_sig_and_pubkey() {
        let (full_sig_hex, pubkey_hex, script) = sig_pubkey_script(0x11, 0x22);
        let witness =
            assemble_p2wpkh_witness(&full_sig_hex, &pubkey_hex, &script).expect("assembles");
        let items: Vec<&[u8]> = witness.iter().collect();
        assert_eq!(items.len(), 2, "P2WPKH witness has 2 items");
        // Item 0: DER signature ending in the SIGHASH_ALL byte; item 1: the 33-byte pubkey.
        assert_eq!(*items[0].last().unwrap(), EcdsaSighashType::All as u8);
        assert_eq!(items[0][0], 0x30, "DER sequence tag");
        assert_eq!(items[1].len(), 33);
    }

    #[test]
    fn rejects_pubkey_that_does_not_control_the_input() {
        let (full_sig_hex, pubkey_hex, _script) = sig_pubkey_script(0x11, 0x22);
        // A script for a *different* key — the returned pubkey must not satisfy it.
        let (_, _, other_script) = sig_pubkey_script(0x99, 0x22);
        let err = assemble_p2wpkh_witness(&full_sig_hex, &pubkey_hex, &other_script).unwrap_err();
        assert!(matches!(err, FireblocksError::Witness(_)));
    }

    #[test]
    fn rejects_malformed_signature_hex() {
        let (_, _, script) = sig_pubkey_script(0x11, 0x22);
        assert!(assemble_p2wpkh_witness("not-hex", "00", &script).is_err());
        // Right hex, wrong length for a compact signature.
        assert!(assemble_p2wpkh_witness("aabb", "00", &script).is_err());
    }

    #[test]
    fn rejects_bad_pubkey() {
        let (full_sig_hex, _, script) = sig_pubkey_script(0x33, 0x44);
        assert!(assemble_p2wpkh_witness(&full_sig_hex, "deadbeef", &script).is_err());
    }
}
