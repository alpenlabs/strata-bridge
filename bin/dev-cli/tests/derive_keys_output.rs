use std::process::Command;

use serde_json::Value;

#[test]
fn derive_keys_output_does_not_expose_seed() {
    let test_seed = "000102030405060708090a0b0c0d0e0f000102030405060708090a0b0c0d0e0f";
    let output = Command::new(env!("CARGO_BIN_EXE_dev-cli"))
        .args(["derive-keys", test_seed, "regtest"])
        .output()
        .expect("failed to run dev-cli derive-keys");

    assert!(
        output.status.success(),
        "derive-keys failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let json: Value =
        serde_json::from_slice(&output.stdout).expect("derive-keys output must be valid JSON");

    assert!(
        json.get("seed").is_none(),
        "derive-keys output must never contain private seed material"
    );

    for field in [
        "general_wallet_address",
        "general_wallet_descriptor",
        "reserved_wallet_address",
        "musig2_key",
        "p2p_key",
    ] {
        assert!(json.get(field).is_some(), "missing public field: {field}");
    }
}
