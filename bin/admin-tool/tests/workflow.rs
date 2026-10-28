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
    taproot,
    transaction::Version,
    Amount, Network, OutPoint, Transaction, TxIn, TxOut, Txid, Witness,
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use corepc_node::{Conf, Node};
use serde_json::{json, Value};
use strata_bridge_connectors::{
    prelude::{AdminSignature, ClaimPayoutConnector},
    Connector,
};
use strata_bridge_tx_graph::transactions::prelude::{AdminBurnData, AdminBurnTx};

fn public_key(byte: u8) -> bitcoin::XOnlyPublicKey {
    Keypair::from_seckey_slice(SECP256K1, &[byte; 32])
        .unwrap()
        .x_only_public_key()
        .0
}

fn run(config: &Path, claim: Txid, hash: sha256::Hash, key: Option<&Path>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_admin-tool"));
    command.arg("--config").arg(config);
    command.arg(if key.is_some() { "sign" } else { "inspect" });
    command.args([
        "--claim-txid",
        &claim.to_string(),
        "--unstaking-hash",
        &hash.to_string(),
    ]);
    if let Some(path) = key {
        command.arg("--signer-file").arg(path);
    }
    command.output().unwrap()
}

fn assert_failure(output: Output, message: &str) {
    assert!(!output.status.success());
    assert!(
        output.stdout.is_empty(),
        "a failed command must not export a signature"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(message),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn inspect_sign_and_publish_with_separate_funding() {
    let mut conf = Conf::default();
    conf.args.push("-txindex=1");
    let node = Node::with_conf("bitcoind", &conf).unwrap();
    let rpc = Client::new(
        &node.rpc_url(),
        Auth::CookieFile(node.params.cookie_file.clone()),
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
    fs::copy(
        &node.params.cookie_file,
        directory.path().join("rpc.cookie"),
    )
    .unwrap();
    let config = directory.path().join("admin-tool.toml");
    let config_text = toml::to_string(&json!({
        "network": "regtest",
        "n_of_n_pubkey": public_key(4).to_string(),
        "admin_pubkeys": admin_keys.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "threshold": 2,
        "rpc": {"url": node.rpc_url(), "cookie_file": "rpc.cookie"},
    }))
    .unwrap();
    fs::write(&config, &config_text).unwrap();

    // Inspection works without any private key file and reports the matched connector.
    let inspected = run(&config, claim_txid, hash, None);
    assert!(
        inspected.status.success(),
        "{}",
        String::from_utf8_lossy(&inspected.stderr)
    );
    let review = String::from_utf8(inspected.stdout).unwrap();
    assert!(review.contains(&format!("{claim_txid}:1")));
    assert!(review.contains("Matches claim output; currently unspent"));
    assert!(review.contains("NONE | ANYONECANPAY (0x82)"));
    for key in &admin_keys {
        assert!(review.contains(&key.to_string()));
    }

    let first_key = directory.path().join("admin-1");
    fs::write(&first_key, "01".repeat(32)).unwrap();
    let wrong_network = directory.path().join("wrong-network.toml");
    fs::write(&wrong_network, config_text.replace("regtest", "signet")).unwrap();
    assert_failure(
        run(&wrong_network, claim_txid, hash, Some(&first_key)),
        "config expects signet",
    );
    assert_failure(
        run(
            &config,
            claim_txid,
            sha256::Hash::hash(&[8; 32]),
            Some(&first_key),
        ),
        "does not match claim output 1",
    );
    let unknown_key = directory.path().join("unknown-admin");
    fs::write(&unknown_key, "09".repeat(32)).unwrap();
    assert_failure(
        run(&config, claim_txid, hash, Some(&unknown_key)),
        "not in the admin set",
    );

    // Two admins export independently. Neither command changes the node's mempool.
    let mempool_before = rpc.get_raw_mempool().unwrap();
    let mut signatures = Vec::new();
    let mut digest = None;
    for (index, admin_key) in admin_keys.iter().enumerate().take(2) {
        let key = directory.path().join(format!("admin-{}", index + 1));
        fs::write(&key, format!("{:02x}", index + 1).repeat(32)).unwrap();
        let signed = run(&config, claim_txid, hash, Some(&key));
        assert!(
            signed.status.success(),
            "{}",
            String::from_utf8_lossy(&signed.stderr)
        );
        assert!(String::from_utf8_lossy(&signed.stderr).contains("The publisher can add funding"));
        let output: Value = serde_json::from_slice(&signed.stdout).unwrap();
        assert_eq!(output["claim_outpoint"], format!("{claim_txid}:1"));
        assert_eq!(output["admin_index"], index);
        assert_eq!(output["admin_public_key"], admin_key.to_string());
        assert_eq!(output["sighash_type"], "0x82");
        if let Some(expected) = &digest {
            assert_eq!(&output["signing_digest"], expected);
        }
        digest = Some(output["signing_digest"].clone());
        assert!(review.contains(output["signing_digest"].as_str().unwrap()));
        let bytes = Vec::from_hex(output["signature"].as_str().unwrap()).unwrap();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[64], 0x82);
        signatures.push(AdminSignature {
            pubkey_index: index,
            signature: taproot::Signature::from_slice(&bytes).unwrap(),
        });
    }
    assert_eq!(rpc.get_raw_mempool().unwrap(), mempool_before);
    assert!(rpc
        .get_tx_out(&claim_txid, 1, Some(true))
        .unwrap()
        .is_some());

    // An independent publisher adds funding and outputs using the existing bridge builder.
    let funding = rpc.get_block(&blocks[1]).unwrap().txdata[0].clone();
    let mut burn = AdminBurnTx::new(AdminBurnData { claim_txid }, connector.clone());
    burn.push_input(
        TxIn {
            previous_output: OutPoint::new(funding.compute_txid(), 0),
            ..Default::default()
        },
        funding.output[0].clone(),
    );
    burn.push_output(TxOut {
        value: funding.output[0].value + connector.value() - Amount::from_sat(1_000),
        script_pubkey: address.script_pubkey(),
    });
    let burn = burn.finalize_partial(signatures);
    let funded = rpc
        .sign_raw_transaction_with_wallet(&burn, None, None)
        .unwrap();
    assert!(funded.complete);
    let funded = funded.transaction().unwrap();

    // Dropping 0x82 makes Core interpret this signature as SIGHASH_DEFAULT.
    let mut invalid = funded.clone();
    let mut witness = invalid.input[0].witness.to_vec();
    witness[1].truncate(64);
    invalid.input[0].witness = Witness::from_slice(&witness);
    let rejected = rpc.test_mempool_accept(&[&invalid]).unwrap();
    assert!(!rejected[0].allowed);

    let burn_txid = rpc.send_raw_transaction(&funded).unwrap();

    // Both commands reject the now-spent connector, including an unconfirmed mempool spend.
    assert_failure(run(&config, claim_txid, hash, None), "spent or unavailable");
    assert_failure(
        run(&config, claim_txid, hash, Some(&first_key)),
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
