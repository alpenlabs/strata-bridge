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
