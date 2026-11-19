//! Signing of the vault inputs of a transaction, and witness assembly from Fireblocks ECDSA
//! signatures.
//!
//! Fireblocks returns a raw `r || s` ECDSA signature (`fullSig`, 64 bytes hex) plus the
//! signing public key for each message. For a P2WPKH input the witness is
//! `[DER(sig) || SIGHASH_ALL, compressed_pubkey]`, so this converts the compact signature to
//! DER, low-S-normalises it (Bitcoin standardness requires low-S), appends the sighash-type byte,
//! and pairs it with the pubkey.
//!
//! Crucially it also performs two checks against the untrusted RAW-signing response before
//! trusting the witness — RAW signing lets Fireblocks choose the signing key and returns a bare
//! `r||s`, so a wrong key or a signature that doesn't match the sighash would otherwise yield a
//! structurally valid but invalid witness that only fails at broadcast:
//! 1. the returned pubkey actually controls the input — `hash160(pubkey)` must equal the input's
//!    P2WPKH witness program; and
//! 2. the signature actually verifies against the `sighash` we asked Fireblocks to sign.

use std::collections::HashSet;

use bdk_wallet::bitcoin::{
    ecdsa,
    hashes::Hash,
    secp256k1::{ecdsa::Signature as SecpSignature, Message, Secp256k1},
    sighash::SighashCache,
    CompressedPublicKey, EcdsaSighashType, Script, ScriptBuf, Transaction, TxOut, Witness,
};

use super::{FireblocksError, FireblocksSigner};

impl FireblocksSigner {
    /// Signs the inputs that spend the vault script. An input that spends any other script
    /// returns `None`: a Fireblocks operator still holds payouts at the general key, and the
    /// caller signs those through secret-service.
    ///
    /// See [`GeneralSigner::sign_owned_inputs`](crate::general::GeneralSigner::sign_owned_inputs)
    /// for the contract of the arguments.
    pub(crate) async fn sign_owned_inputs(
        &self,
        tx: &Transaction,
        input_indices: &[usize],
        prevouts: &[TxOut],
    ) -> Result<Vec<Option<Witness>>, FireblocksError> {
        // A missing prevout must not read as an input off the vault script: the caller would send
        // a vault input to secret-service, which holds no key for it.
        if prevouts.len() != tx.input.len() || input_indices.iter().any(|&i| i >= prevouts.len()) {
            return Err(FireblocksError::SignRequest(format!(
                "{} prevouts for {} inputs, signing indices {input_indices:?}",
                prevouts.len(),
                tx.input.len(),
            )));
        }
        // A repeated index gives a repeated sighash. Two inputs of one transaction never share a
        // sighash, because each commits to its own outpoint.
        let distinct: HashSet<usize> = input_indices.iter().copied().collect();
        if distinct.len() != input_indices.len() {
            return Err(FireblocksError::SignRequest(format!(
                "repeated signing index in {input_indices:?}"
            )));
        }
        // Positions in `input_indices` of the inputs that spend the vault script.
        let owned: Vec<usize> = (0..input_indices.len())
            .filter(|&slot| prevouts[input_indices[slot]].script_pubkey == self.script_pubkey)
            .collect();
        let mut witnesses = vec![None; input_indices.len()];
        if owned.is_empty() {
            return Ok(witnesses);
        }
        let sighashes = owned
            .iter()
            .map(|&slot| {
                let i = input_indices[slot];
                p2wpkh_sighash(tx, i, &prevouts[i])
            })
            .collect::<Result<Vec<_>, _>>()?;
        let signed = self
            .raw_sign(&sighashes, &tx.compute_txid().to_string())
            .await?;

        for ((message, sighash), &slot) in signed.iter().zip(&sighashes).zip(&owned) {
            // Verifies that the returned pubkey controls this prevout (assemble_p2wpkh_witness
            // checks hash160 == witness program) and that the signature covers this sighash.
            // A completed request keeps its signatures, so a bad one retires the request.
            let witness = assemble_p2wpkh_witness(
                &message.signature.full_sig,
                &message.public_key,
                &prevouts[input_indices[slot]].script_pubkey,
                sighash,
            )
            .inspect_err(|_| self.retire_request(&sighashes))?;
            witnesses[slot] = Some(witness);
        }
        Ok(witnesses)
    }
}

/// Computes the BIP-143 sighash (SIGHASH_ALL) for the P2WPKH input at `input_index` of `tx`, which
/// spends `prevout`.
fn p2wpkh_sighash(
    tx: &Transaction,
    input_index: usize,
    prevout: &TxOut,
) -> Result<[u8; 32], FireblocksError> {
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            input_index,
            &prevout.script_pubkey,
            prevout.value,
            EcdsaSighashType::All,
        )
        .map_err(|e| {
            FireblocksError::SignRequest(format!("p2wpkh sighash (input {input_index}): {e}"))
        })?;
    Ok(sighash.to_byte_array())
}

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
    // A high-S signature is valid but does not relay; Fireblocks usually returns low-S already, but
    // normalise to be safe.
    signature.normalize_s();

    let ecdsa_sig = ecdsa::Signature {
        signature,
        sighash_type: EcdsaSighashType::All,
    };

    let pubkey_bytes = hex::decode(public_key_hex)
        .map_err(|e| FireblocksError::Witness(format!("pubkey hex: {e}")))?;
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
    // bad/garbled `fullSig` here rather than letting an invalid witness fail at broadcast. This
    // check accepts only low-S signatures, so it must run after `normalize_s`.
    Secp256k1::verification_only()
        .verify_ecdsa(&Message::from_digest(*sighash), &signature, &compressed.0)
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
    use bdk_wallet::bitcoin::{
        absolute::LockTime,
        consensus::encode::deserialize_hex,
        secp256k1::{self, Message, Secp256k1, SecretKey},
        transaction::Version,
        Amount, OutPoint, Sequence, TxIn,
    };
    use wiremock::MockServer;

    use super::*;
    use crate::general::fireblocks::test_utils::{
        created, details, expect, mock_signer, offline_signer, ok, vault_pubkey, CREATE_PATH,
        TX_PATH, VAULT_SECRET,
    };

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

    /// A high-S compact signature must be normalized to low-S before DER-encoding (Bitcoin
    /// relay rejects high-S). `sign_ecdsa` always returns low-S, so flip it to its high-S
    /// counterpart `(r, n - s)`, feed that through, and confirm the assembled DER signature
    /// carries the original low-S `s`.
    #[test]
    fn normalizes_high_s_signature() {
        let (low_s_hex, pubkey_hex, script, sighash) = sig_pubkey_script(0x55, 0x66);
        let low_compact: [u8; 32 * 2] = hex::decode(&low_s_hex).unwrap().try_into().unwrap();
        let low_s: [u8; 32] = low_compact[32..].try_into().unwrap();

        // High-S form: r unchanged, s -> n - s.
        let high_s = SecretKey::from_slice(&low_s)
            .unwrap()
            .negate()
            .secret_bytes();
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

    /// The native P2WPKH example of BIP-143.
    #[test]
    fn the_sighash_matches_the_bip143_example() {
        let tx: Transaction = deserialize_hex(
            "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f000000\
             0000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a01000000\
             00ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093\
             510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000",
        )
        .expect("the example transaction");
        let prevout = TxOut {
            value: Amount::from_sat(600_000_000),
            script_pubkey: ScriptBuf::from_hex("00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1")
                .expect("the example script"),
        };

        let sighash = p2wpkh_sighash(&tx, 1, &prevout).expect("sighash");

        assert_eq!(
            hex::encode(sighash),
            "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670"
        );
    }

    /// A Fireblocks operator keeps payouts at the general key, and only secret-service can sign
    /// those. The signer leaves them to the caller and does not ask the vault.
    #[tokio::test]
    async fn an_input_off_the_vault_script_is_left_for_the_caller() {
        let tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                ..TxIn::default()
            }],
            output: Vec::new(),
        };
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_op_return([]),
        };
        let witnesses = offline_signer()
            .sign_owned_inputs(&tx, &[0], &[prevout])
            .await
            .expect("no vault input, so no API call");
        assert_eq!(witnesses, vec![None]);
    }

    #[tokio::test]
    async fn a_signing_index_past_the_inputs_is_an_error() {
        let tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: Vec::new(),
        };
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_op_return([]),
        };
        let err = offline_signer()
            .sign_owned_inputs(&tx, &[1], &[prevout])
            .await
            .expect_err("input 1 does not exist");
        assert!(
            matches!(err, FireblocksError::SignRequest(_)),
            "got {err:?}"
        );
    }

    /// One signature must not fill two entries of the result.
    #[tokio::test]
    async fn a_repeated_signing_index_is_an_error() {
        let signer = offline_signer();
        let tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: Vec::new(),
        };
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: signer.script_pubkey.clone(),
        };
        let err = signer
            .sign_owned_inputs(&tx, &[0, 0], &[prevout])
            .await
            .expect_err("index 0 appears twice");
        assert!(
            matches!(err, FireblocksError::SignRequest(_)),
            "got {err:?}"
        );
    }

    /// A `None` slot goes to secret-service, so a witness in the wrong slot means a wrong signer.
    /// The server answers in reverse order: position in the response must not bind a signature.
    #[tokio::test]
    async fn each_vault_input_gets_its_own_witness_in_a_mixed_transaction() {
        let server = MockServer::start().await;
        let signer = mock_signer(&server);
        let tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: (0..3)
                .map(|vout| TxIn {
                    previous_output: OutPoint::new(bdk_wallet::bitcoin::Txid::all_zeros(), vout),
                    ..TxIn::default()
                })
                .collect(),
            output: Vec::new(),
        };
        let vault_prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: signer.script_pubkey.clone(),
        };
        let foreign_prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_op_return([]),
        };
        let prevouts = [
            vault_prevout.clone(),
            foreign_prevout,
            vault_prevout.clone(),
        ];
        let sighash_0 = p2wpkh_sighash(&tx, 0, &vault_prevout).expect("sighash");
        let sighash_2 = p2wpkh_sighash(&tx, 2, &vault_prevout).expect("sighash");
        expect(&server, "POST", CREATE_PATH, created(), 1).await;
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[sighash_2, sighash_0], &VAULT_SECRET)),
            1,
        )
        .await;

        let witnesses = signer
            .sign_owned_inputs(&tx, &[0, 1, 2], &prevouts)
            .await
            .expect("signed");

        assert_eq!(witnesses[1], None, "secret-service signs this input");
        let secp = Secp256k1::verification_only();
        for (slot, sighash) in [(0, sighash_0), (2, sighash_2)] {
            let witness = witnesses[slot].as_ref().expect("a vault input");
            let der = witness.nth(0).expect("a signature");
            let signature =
                bdk_wallet::bitcoin::secp256k1::ecdsa::Signature::from_der(&der[..der.len() - 1])
                    .expect("DER signature");
            secp.verify_ecdsa(&Message::from_digest(sighash), &signature, &vault_pubkey())
                .expect("the witness of this slot signs this input");
        }
    }

    /// A completed request whose signature fails verification comes back under the same id on
    /// every attempt, so the failure moves its sighash set to the next generation.
    #[tokio::test]
    async fn a_signature_that_fails_verification_retires_its_request() {
        let server = MockServer::start().await;
        let signer = mock_signer(&server);
        let tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: Vec::new(),
        };
        let prevout = TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: signer.script_pubkey.clone(),
        };
        let sighash = p2wpkh_sighash(&tx, 0, &prevout).expect("sighash");
        expect(&server, "POST", CREATE_PATH, created(), 1).await;
        let other_secret = [9; 32];
        expect(
            &server,
            "GET",
            TX_PATH,
            ok(details("COMPLETED", &[sighash], &other_secret)),
            1,
        )
        .await;

        signer
            .sign_owned_inputs(&tx, &[0], &[prevout])
            .await
            .expect_err("a signature of another key fails verification");

        let generations: Vec<u64> = signer
            .generations
            .lock()
            .expect("no panic holds the generation map")
            .values()
            .copied()
            .collect();
        assert_eq!(
            generations,
            vec![1],
            "the next attempt creates a request of the next generation"
        );
    }

    /// A vault input with no prevout must not go to secret-service as an input off the vault.
    #[tokio::test]
    async fn a_short_prevout_list_is_an_error() {
        let tx = Transaction {
            version: Version(3),
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: Vec::new(),
        };
        let err = offline_signer()
            .sign_owned_inputs(&tx, &[0], &[])
            .await
            .expect_err("the prevout of input 0 is missing");
        assert!(
            matches!(err, FireblocksError::SignRequest(_)),
            "got {err:?}"
        );
    }
}
