//! Witness assembly from Fireblocks ECDSA signatures.
//!
//! Fireblocks returns a raw `r || s` ECDSA signature (`fullSig`, 64 bytes hex) plus the
//! signing public key for each message. For a P2WPKH input the witness is
//! `[DER(sig) || SIGHASH_ALL, compressed_pubkey]`, so this converts the compact signature to
//! DER, low-S-normalises it (Bitcoin consensus requires low-S), appends the sighash-type byte,
//! and pairs it with the pubkey.

use bdk_wallet::bitcoin::{
    ecdsa,
    secp256k1::{self, ecdsa::Signature as SecpSignature},
    EcdsaSighashType, Witness,
};

use super::FireblocksError;

/// Builds the P2WPKH witness for one input from Fireblocks' `fullSig` (hex `r||s`) and the
/// signing public key (hex, compressed). Low-S-normalises the signature before DER-encoding.
pub(super) fn assemble_p2wpkh_witness(
    full_sig_hex: &str,
    public_key_hex: &str,
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

    let mut witness = Witness::new();
    witness.push(ecdsa_sig.to_vec());
    witness.push(&pubkey_bytes);
    Ok(witness)
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::secp256k1::{Message, Secp256k1, SecretKey};

    use super::*;

    #[test]
    fn assembles_witness_with_der_sig_and_pubkey() {
        // Produce a real signature so the compact->DER path exercises valid inputs.
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let msg = Message::from_digest([0x22; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);

        let full_sig_hex = hex::encode(sig.serialize_compact());
        let pubkey_hex = hex::encode(pk.serialize());

        let witness = assemble_p2wpkh_witness(&full_sig_hex, &pubkey_hex).expect("assembles");
        let items: Vec<&[u8]> = witness.iter().collect();
        assert_eq!(items.len(), 2, "P2WPKH witness has 2 items");

        // Item 0: DER signature ending in the SIGHASH_ALL byte.
        assert_eq!(*items[0].last().unwrap(), EcdsaSighashType::All as u8);
        // DER sequence tag.
        assert_eq!(items[0][0], 0x30);
        // Item 1: the 33-byte compressed pubkey.
        assert_eq!(items[1].len(), 33);
        assert_eq!(items[1], pk.serialize());
    }

    #[test]
    fn rejects_malformed_signature_hex() {
        assert!(assemble_p2wpkh_witness("not-hex", "00").is_err());
        // Right hex, wrong length for a compact signature.
        assert!(assemble_p2wpkh_witness("aabb", "00").is_err());
    }

    #[test]
    fn rejects_bad_pubkey() {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x33; 32]).unwrap();
        let msg = Message::from_digest([0x44; 32]);
        let sig = secp.sign_ecdsa(&msg, &sk);
        let full_sig_hex = hex::encode(sig.serialize_compact());
        assert!(assemble_p2wpkh_witness(&full_sig_hex, "deadbeef").is_err());
    }
}
