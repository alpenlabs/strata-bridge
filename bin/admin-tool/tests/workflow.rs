//! Exercise the actual CLI against Bitcoin Core, including a later-funded threshold spend.

#![expect(
    unused_crate_dependencies,
    reason = "Binary dependencies are exercised through the CLI subprocess"
)]

use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

use bitcoin::{
    absolute,
    hashes::{sha256, Hash},
    hex::FromHex,
    secp256k1::{Keypair, SECP256K1},
    transaction::Version,
    Amount, Network, OutPoint, Transaction, TxIn, TxOut, Txid,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use corepc_node::{Conf, Node};
use serde_json::{json, Value};
use strata_bridge_connectors::{prelude::ClaimPayoutConnector, Connector};

fn public_key(byte: u8) -> bitcoin::XOnlyPublicKey {
    Keypair::from_seckey_slice(SECP256K1, &[byte; 32])
        .unwrap()
        .x_only_public_key()
        .0
}

fn command(
    config: &Path,
    params: &Path,
    claim: Txid,
    hash: sha256::Hash,
    operation: &str,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_admin-tool"));
    command.arg("--config").arg(config);
    command.arg("--params").arg(params);
    command.arg(operation);
    command.args([
        "--claim-txid",
        &claim.to_string(),
        "--unstaking-hash",
        &hash.to_string(),
    ]);
    command
}

fn run(
    config: &Path,
    params: &Path,
    claim: Txid,
    hash: sha256::Hash,
    key: Option<&Path>,
) -> Output {
    let operation = if key.is_some() { "sign" } else { "inspect" };
    let mut command = command(config, params, claim, hash, operation);
    if let Some(path) = key {
        command.arg("--signer-file").arg(path);
    }
    command.output().unwrap()
}

fn assert_failure(output: Output, message: &str) {
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "a failed command must not export a signature or transaction"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(message),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inspect_sign_assemble_and_publish_with_separate_funding() {
    let mut conf = Conf::default();
    conf.args.push("-txindex=1");
    let node = Node::with_conf("bitcoind", &conf).unwrap();
    let credentials = node.params.get_cookie_values().unwrap().unwrap();
    let rpc = Client::new(
        &node.rpc_url(),
        Auth::UserPass(credentials.user.clone(), credentials.password.clone()),
    )
    .unwrap();
    let address = rpc
        .get_new_address(None, None)
        .unwrap()
        .require_network(Network::Regtest)
        .unwrap();
    let blocks = rpc.generate_to_address(101, &address).unwrap();
    let coinbase = rpc.get_block(&blocks[0]).unwrap().txdata[0].clone();
    let hash = sha256::Hash::hash(&[5; 32]);
    let admin_keys: Vec<_> = (1..=3).map(public_key).collect();
    let connector =
        ClaimPayoutConnector::new(Network::Regtest, public_key(4), admin_keys.clone(), 2, hash);
    let claim = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(coinbase.compute_txid(), 0),
            ..Default::default()
        }],
        output: vec![
            TxOut {
                value: coinbase.output[0].value - connector.value() - Amount::from_sat(1_000),
                script_pubkey: address.script_pubkey(),
            },
            connector.tx_out(),
        ],
    };
    let signed = rpc
        .sign_raw_transaction_with_wallet(&claim, None, None)
        .unwrap();
    assert!(signed.complete);
    let claim_txid = rpc
        .send_raw_transaction(&signed.transaction().unwrap())
        .unwrap();
    rpc.generate_to_address(1, &address).unwrap();

    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("admin-tool.toml");
    let config_text = format!(
        r#"n_of_n_pubkey = "{internal_key}"

[rpc]
url = "{url}"
username = "{username}"
password = "{password}"
"#,
        internal_key = public_key(4),
        url = node.rpc_url(),
        username = credentials.user,
        password = credentials.password,
    );

    fs::write(&config, &config_text).unwrap();

    let params = directory.path().join("params.toml");
    let params_text = format!(
        r#"network = "regtest"
genesis_height = 101

[keys]
operators = []

[keys.admin]
pubkeys = ["{admin_a}", "{admin_b}", "{admin_c}"]
threshold = 2

[protocol]
bury_depth = 2
magic_bytes = "ALPN"
deposit_amount = 1_000_000_000
stake_amount = 100_000_000
operator_fee = 10_000_000
sweep_fee_rate = 10
recovery_delay = 1_008
contest_timelock = 144
proof_timelock = 144
ack_timelock = 432
nack_timelock = 144
contested_payout_timelock = 1_008
unstaking_timelock = 2_016
"#,
        admin_a = admin_keys[0],
        admin_b = admin_keys[1],
        admin_c = admin_keys[2],
    );

    fs::write(&params, &params_text).unwrap();

    // Inspection works without any private key file and reports the matched connector.
    let inspected = run(&config, &params, claim_txid, hash, None);

    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let review = String::from_utf8(inspected.stdout).unwrap();

    assert!(review.contains(&format!("{claim_txid}:1")));
    assert!(review.contains("Matches claim output; currently unspent"));
    assert!(review.contains("NONE | ANYONECANPAY (0x82)"));

    let first_key = directory.path().join("admin-1");
    fs::write(&first_key, "01".repeat(32)).unwrap();
    let wrong_network = directory.path().join("wrong-network.toml");
    fs::write(&wrong_network, params_text.replace("regtest", "signet")).unwrap();

    assert_failure(
        run(&config, &wrong_network, claim_txid, hash, Some(&first_key)),
        "bridge params expect signet",
    );

    // Two admins export independently. Neither command changes the node's mempool.
    let mempool_before = rpc.get_raw_mempool().unwrap();
    let mut signatures = Vec::new();
    for (index, admin_key) in admin_keys.iter().enumerate().take(2) {
        let key = directory.path().join(format!("admin-{}", index + 1));
        fs::write(&key, format!("{:02x}", index + 1).repeat(32)).unwrap();

        let signed = run(&config, &params, claim_txid, hash, Some(&key));

        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
        let summary = String::from_utf8(signed.stderr).unwrap();

        assert!(summary.contains("The publisher can add funding"));
        assert!(summary.contains(&format!("Signing admin:     {admin_key}")));

        let signature = String::from_utf8(signed.stdout).unwrap();
        let bytes = Vec::from_hex(signature.trim()).unwrap();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[64], 0x82);
        signatures.push(signature.trim().to_owned());
    }

    // Assembly needs only the shared signatures, not a private key.
    let mut assemble = command(&config, &params, claim_txid, hash, "assemble");
    for signature in signatures {
        assemble.arg("--signature").arg(signature);
    }

    let assembled = assemble.output().unwrap();

    assert!(
        assembled.status.success(),
        "{}",
        String::from_utf8_lossy(&assembled.stderr)
    );
    let summary = String::from_utf8(assembled.stderr).unwrap();

    assert!(summary.contains(&format!("Included admin [0]: {}", admin_keys[0])));
    assert!(summary.contains(&format!("Included admin [1]: {}", admin_keys[1])));
    assert!(!summary.contains("Included admin [2]:"));

    let input_weight: u64 = summary
        .lines()
        .find_map(|line| line.strip_prefix("Connector input weight: "))
        .unwrap()
        .strip_suffix(" WU")
        .unwrap()
        .parse()
        .unwrap();

    let hex = String::from_utf8(assembled.stdout).unwrap();
    let burn: Transaction =
        bitcoin::consensus::deserialize(&Vec::from_hex(hex.trim()).unwrap()).unwrap();

    assert_eq!(burn.input.len(), 1);
    assert_eq!(burn.input[0].previous_output, OutPoint::new(claim_txid, 1));
    assert_eq!(burn.output[0].value, Amount::ZERO);
    assert!(burn.output[0].script_pubkey.is_op_return());
    assert_eq!(rpc.get_raw_mempool().unwrap(), mempool_before);

    // Core's external wallet selects funding and change while preserving the admin witness.
    let funding: Value = rpc
        .call(
            "fundrawtransaction",
            &[
                json!(hex.trim()),
                json!({
                    "fee_rate": 10,
                    "minconf": 1,
                    "input_weights": [{
                        "txid": claim_txid,
                        "vout": 1,
                        "weight": input_weight,
                    }],
                }),
                json!(true),
            ],
        )
        .unwrap();
    let wallet_funded: Transaction =
        bitcoin::consensus::deserialize(&Vec::from_hex(funding["hex"].as_str().unwrap()).unwrap())
            .unwrap();
    assert!(wallet_funded.input.len() > 1);
    assert_eq!(wallet_funded.input[0], burn.input[0]);

    let funded = rpc
        .sign_raw_transaction_with_wallet(&wallet_funded, None, None)
        .unwrap();
    assert!(funded.complete);
    let funded = funded.transaction().unwrap();

    let burn_txid = rpc.send_raw_transaction(&funded).unwrap();

    // Signing checks unspent status again, including the burn now in the mempool.
    assert_failure(
        run(&config, &params, claim_txid, hash, Some(&first_key)),
        "spent or unavailable",
    );

    let mined = rpc.generate_to_address(1, &address).unwrap();

    assert!(rpc
        .get_block(&mined[0])
        .unwrap()
        .txdata
        .iter()
        .any(|tx| tx.compute_txid() == burn_txid));
}
