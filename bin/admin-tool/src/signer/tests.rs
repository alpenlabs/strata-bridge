use std::{fs, io::Write};

use super::*;

#[tokio::test]
async fn loads_existing_hex_key_and_signs_without_tweaking() {
    let encoded = format!("  {}\n", "01".repeat(32));
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(encoded.as_bytes()).unwrap();

    let signer = FileAdminSigner::from_path(file.path()).unwrap();
    let expected = Keypair::from_seckey_slice(SECP256K1, &[1; 32]).unwrap();
    let public_key = signer.public_key().await.unwrap();
    assert_eq!(public_key, expected.x_only_public_key().0);

    let digest = [42; 32];
    let signature = signer.sign_digest(digest).await.unwrap();
    SECP256K1
        .verify_schnorr(&signature, &Message::from_digest(digest), &public_key)
        .unwrap();

    assert_eq!(fs::read_to_string(file.path()).unwrap(), encoded);
    assert!(!format!("{signer:?}").contains(&"01".repeat(32)));
}

#[test]
fn rejects_invalid_keys_without_exposing_the_contents() {
    for encoded in [
        "secret input".to_owned(),
        "00".repeat(32),
        "ff".repeat(32),
        "01".repeat(33),
        "g1".repeat(32),
        format!("{}{}extra", "01".repeat(32), " ".repeat(192)),
    ] {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(encoded.as_bytes()).unwrap();

        let error = FileAdminSigner::from_path(file.path()).unwrap_err();
        assert!(!error.to_string().contains(&encoded));
    }
}

#[tokio::test]
async fn derives_covenant_signer_from_raw_seed_without_exporting_a_key() {
    let seed = [42; 32];
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&seed).unwrap();
    let signer = FileAdminSigner::from_operator_seed_path(file.path(), Network::Signet).unwrap();

    // Independent full-path derivation checks that the operator base branch is included.
    let master = Xpriv::new_master(Network::Signet, &seed).unwrap();
    let path: bitcoin::bip32::DerivationPath = "m/20000'/20'/20'/101'".parse().unwrap();
    let child = master.derive_priv(SECP256K1, &path).unwrap();
    let expected = Keypair::from_secret_key(SECP256K1, &child.private_key);
    let public_key = signer.public_key().await.unwrap();
    assert_eq!(public_key, expected.x_only_public_key().0);

    let digest = [7; 32];
    let signature = signer.sign_digest(digest).await.unwrap();
    SECP256K1
        .verify_schnorr(&signature, &Message::from_digest(digest), &public_key)
        .unwrap();
    assert_eq!(fs::read(file.path()).unwrap(), seed);
    assert!(!format!("{signer:?}").contains(&hex::encode(seed)));
    assert!(!format!("{signer:?}").contains(&hex::encode(child.private_key.secret_bytes())));
}

#[test]
fn rejects_seed_files_that_are_not_exactly_32_raw_bytes() {
    for contents in [
        vec![],
        vec![42; 31],
        vec![42; 33],
        "2a".repeat(32).into_bytes(),
        vec![42; 1_000],
    ] {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&contents).unwrap();
        let error =
            FileAdminSigner::from_operator_seed_path(file.path(), Network::Signet).unwrap_err();
        assert!(error.to_string().contains("exactly 32 raw bytes"));
        if !contents.is_empty() {
            assert!(!error.to_string().contains(&hex::encode(contents)));
        }
    }
}
