#![allow(unused_crate_dependencies)]
//! Crate-level integration tests for `operator-wallet` against a real `bitcoind` regtest
//! node (via `corepc-node`).
//!
//! These tests cover the load-bearing surface of [`OperatorWallet`]:
//!
//! - **Lease bookkeeping** is idempotent and additive (lease + release semantics).
//! - **Reserved-UTXO creation** funds the reserved wallet with the requested denomination +
//!   quantity, and the resulting UTXOs are discoverable via `reserved_utxos_with_value`.
//! - **Pool refill** semantics: caller computes batch size from current count, requests only the
//!   delta, and the wallet doesn't re-spend existing pool members back to itself.
//! - **Sync prunes stale leases** so a long-running operator doesn't accumulate leases for
//!   outpoints that the chain has already spent.
//!
//! Tests are `#[serial]` because `bitcoind` binds a fixed RPC port — parallel runs would
//! collide. Each test spins up a fresh `bitcoind` so state doesn't leak between cases.
//!
//! Signing of the funded PSBTs (the `create_reserved_utxos` happy path) is performed
//! in-process with the test's known operator privkey: the native general wallet is
//! descriptor-only, so production goes through secret-service. The test bypasses that by
//! signing with the same keypair the descriptor was constructed from (BIP-341 key-path with
//! the empty-merkle-root tap-tweak).

use std::{collections::BTreeSet, sync::Arc};

use bdk_wallet::bitcoin::{
    hashes::Hash,
    key::{Keypair, Secp256k1, TapTweak},
    secp256k1::{Message, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot, Address, Amount, FeeRate, Network, OutPoint, Psbt, TapSighashType, Transaction,
    Witness, XOnlyPublicKey,
};
use corepc_node::{Conf, Node};
use operator_wallet::{
    sync::Backend, GeneralWallet, NativeGeneralWallet, OperatorWallet, OperatorWalletConfig,
};
use serial_test::serial;

/// 1 sat — the smallest possible "anchor" value, used in tests where we don't actually
/// want any UTXO to look like an anchor. `OperatorWallet`'s anchor exclusion filters on
/// (value == cpfp_value) AND (confirmations == 0); none of the test outputs are that small
/// AND unconfirmed-at-query-time, so the filter is a no-op in these tests.
const SENTINEL_ANCHOR_VALUE: Amount = Amount::from_sat(330);

/// Boots a fresh regtest `bitcoind`, mines coinbase maturity, and returns the node.
fn setup_bitcoind() -> Node {
    let bitcoind = Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind must start");
    let mining_address = bitcoind.client.new_address().expect("mining address");
    bitcoind
        .client
        .generate_to_address(101, &mining_address)
        .expect("mine coinbase maturity");
    bitcoind
}

/// Spins up a sync `bitcoincore_rpc::Client` against the running node — needed by
/// `Backend::BitcoinCore`.
fn sync_rpc_client(bitcoind: &Node) -> bdk_bitcoind_rpc::bitcoincore_rpc::Client {
    let cookie_path = bitcoind.params.cookie_file.clone();
    let auth = bdk_bitcoind_rpc::bitcoincore_rpc::Auth::CookieFile(cookie_path);
    bdk_bitcoind_rpc::bitcoincore_rpc::Client::new(&bitcoind.rpc_url(), auth)
        .expect("sync rpc client")
}

/// Constructs a deterministic keypair from `seed`.
fn keypair_from_seed(seed: u8) -> (Keypair, XOnlyPublicKey) {
    let secret = SecretKey::from_slice(&[seed; 32]).expect("valid 32-byte scalar");
    let kp = Keypair::from_secret_key(&Secp256k1::new(), &secret);
    let (xonly, _) = kp.x_only_public_key();
    (kp, xonly)
}

/// Builds a fully-wired `OperatorWallet<NativeGeneralWallet>` for tests. Funds the general
/// wallet with `general_funding_utxos` UTXOs of `general_funding_value` each via bitcoind's
/// own wallet, then syncs. The reserved wallet is created from a separate deterministic
/// keypair and starts empty.
async fn build_operator_wallet(
    bitcoind: &Node,
    general_seed: u8,
    reserved_seed: u8,
    general_funding_utxos: usize,
    general_funding_value: Amount,
) -> (
    OperatorWallet<NativeGeneralWallet>,
    Keypair, // general keypair, used by the test to sign funded PSBTs
    XOnlyPublicKey,
) {
    let (general_kp, general_pubkey) = keypair_from_seed(general_seed);
    let (_reserved_kp, reserved_pubkey) = keypair_from_seed(reserved_seed);

    let general_backend = Backend::BitcoinCore(Arc::new(sync_rpc_client(bitcoind)));
    let reserved_backend = Backend::BitcoinCore(Arc::new(sync_rpc_client(bitcoind)));
    let general = NativeGeneralWallet::new(general_pubkey, Network::Regtest, general_backend);
    let config = OperatorWalletConfig::new(SENTINEL_ANCHOR_VALUE, Network::Regtest);
    let mut wallet = OperatorWallet::new(
        general,
        reserved_pubkey,
        config,
        reserved_backend,
        BTreeSet::new(),
    );

    // Fund the general wallet's address from bitcoind's own wallet.
    let general_address = Address::p2tr(&Secp256k1::new(), general_pubkey, None, Network::Regtest);
    for _ in 0..general_funding_utxos {
        bitcoind
            .client
            .send_to_address(&general_address, general_funding_value)
            .expect("send_to_address");
    }
    let miner_addr = bitcoind.client.new_address().expect("miner address");
    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine confirmation");

    wallet.sync().await.expect("initial wallet sync");
    (wallet, general_kp, general_pubkey)
}

/// Manually signs every input of `psbt` with `keypair` as a Taproot key-path spend
/// (BIP-341 tap-tweak with empty merkle root). Used by the tests to finalize PSBTs that
/// the descriptor-only `NativeGeneralWallet` returns unsigned. Returns the extracted
/// signed transaction.
fn sign_and_finalize(mut psbt: Psbt, keypair: Keypair) -> Transaction {
    let secp = Secp256k1::new();
    let tweaked = keypair.tap_tweak(&secp, None).to_keypair();
    let prevouts: Vec<_> = psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().expect("witness_utxo on every input"))
        .collect();
    let unsigned = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned);
    for i in 0..psbt.inputs.len() {
        let sighash = cache
            .taproot_key_spend_signature_hash(i, &Prevouts::All(&prevouts), TapSighashType::Default)
            .expect("sighash");
        let signature = secp.sign_schnorr_no_aux_rand(&Message::from(sighash), &tweaked);
        psbt.inputs[i].tap_key_sig = Some(taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        });
    }
    for input in &mut psbt.inputs {
        if let Some(sig) = input.tap_key_sig.take() {
            let mut witness = Witness::new();
            witness.push(sig.to_vec());
            input.final_script_witness = Some(witness);
        }
    }
    psbt.extract_tx().expect("extract")
}

#[tokio::test]
#[serial]
async fn lease_release_are_idempotent_and_additive() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, _kp, _pk) =
        build_operator_wallet(&bitcoind, 1, 2, 1, Amount::from_btc(0.5).unwrap()).await;

    let op_a = OutPoint {
        txid: bdk_wallet::bitcoin::Txid::from_slice(&[1u8; 32]).unwrap(),
        vout: 0,
    };
    let op_b = OutPoint {
        txid: bdk_wallet::bitcoin::Txid::from_slice(&[2u8; 32]).unwrap(),
        vout: 1,
    };

    assert!(wallet.leased_outpoints().is_empty(), "starts empty");
    wallet.lease(&[op_a, op_b]);
    assert_eq!(wallet.leased_outpoints().len(), 2, "two leased");
    // Idempotent: re-leasing the same outpoints doesn't grow the set.
    wallet.lease(&[op_a]);
    assert_eq!(
        wallet.leased_outpoints().len(),
        2,
        "still two after re-lease"
    );

    wallet.release(&[op_a]);
    assert_eq!(wallet.leased_outpoints().len(), 1, "one left after release");
    // Release-of-unleased is safe (no panic; logs a warning we don't capture here).
    wallet.release(&[op_a]);
    assert_eq!(wallet.leased_outpoints().len(), 1, "still one");
    wallet.release(&[op_b]);
    assert!(wallet.leased_outpoints().is_empty(), "empty again");
}

#[tokio::test]
#[serial]
async fn create_reserved_utxos_funds_pool_and_leases_inputs() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, general_kp, _) =
        build_operator_wallet(&bitcoind, 3, 4, 3, Amount::from_btc(0.5).unwrap()).await;

    // Create 5 reserved UTXOs of 0.01 BTC each. Bridges the same shape as the claim-funding
    // pool: caller picks the denomination, the composer constructs the funding tx.
    let utxo_value = Amount::from_btc(0.01).unwrap();
    let quantity = 5;
    let fee_rate = FeeRate::from_sat_per_vb(5).unwrap();
    let funded = wallet
        .create_reserved_utxos(fee_rate, utxo_value, quantity)
        .await
        .expect("funding must succeed");

    // The wallet should have leased the funding inputs (so concurrent duties don't double-
    // pick them). The actual leased outpoints come from the funded PSBT's inputs.
    let leased = wallet.leased_outpoints();
    assert!(
        !leased.is_empty(),
        "wallet must have leased the funding inputs"
    );
    for spent in funded.spent() {
        assert!(
            leased.contains(&spent),
            "every spent outpoint must be leased; missing {spent}"
        );
    }

    // The PSBT must carry the requested quantity of reserved-wallet outputs.
    let reserved_script = wallet.reserved_script_pubkey();
    let reserved_output_count = funded
        .psbt
        .unsigned_tx
        .output
        .iter()
        .filter(|o| o.value == utxo_value && o.script_pubkey == reserved_script)
        .count();
    assert_eq!(
        reserved_output_count, quantity,
        "PSBT must contain {quantity} reserved-wallet outputs of {utxo_value}"
    );

    // Sign + broadcast + confirm; resync; the reserved pool now contains the new UTXOs.
    let signed = sign_and_finalize(funded.psbt, general_kp);
    bitcoind
        .client
        .send_raw_transaction(&signed)
        .expect("sendrawtransaction");
    let miner_addr = bitcoind.client.new_address().expect("miner addr");
    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine");
    wallet.sync().await.expect("post-broadcast sync");

    let pool = wallet.reserved_utxos_with_value(utxo_value);
    assert_eq!(
        pool.len(),
        quantity,
        "reserved pool must have {quantity} matching UTXOs"
    );
    for utxo in &pool {
        assert_eq!(utxo.amount, utxo_value);
        assert_eq!(utxo.script_pubkey, reserved_script);
    }
}

#[tokio::test]
#[serial]
async fn reserve_utxo_with_value_picks_and_leases_one() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, general_kp, _) =
        build_operator_wallet(&bitcoind, 5, 6, 3, Amount::from_btc(0.5).unwrap()).await;

    // Seed the reserved pool with 3 UTXOs of 0.01 BTC.
    let utxo_value = Amount::from_btc(0.01).unwrap();
    let funded = wallet
        .create_reserved_utxos(FeeRate::from_sat_per_vb(5).unwrap(), utxo_value, 3)
        .await
        .expect("seed funding");
    let signed = sign_and_finalize(funded.psbt, general_kp);
    bitcoind
        .client
        .send_raw_transaction(&signed)
        .expect("broadcast");
    let miner_addr = bitcoind.client.new_address().expect("miner");
    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine");
    wallet.sync().await.expect("sync");

    // Reset wallet's lease state — the funding-tx inputs were leased; the new reserved
    // UTXOs themselves haven't been. We're testing reserve_utxo_with_value on the pool.
    let funding_inputs: Vec<OutPoint> = wallet.leased_outpoints().iter().copied().collect();
    wallet.release(&funding_inputs);
    assert!(wallet.leased_outpoints().is_empty(), "lease state cleared");

    let (picked, remaining) = wallet.reserve_utxo_with_value(utxo_value, |_| false);
    let picked = picked.expect("must return one outpoint");
    assert_eq!(remaining, 2, "two more left in the pool");
    assert!(
        wallet.leased_outpoints().contains(&picked),
        "picked outpoint must be leased"
    );

    // Picking again skips the leased one; we get a different outpoint.
    let (picked_again, remaining_again) = wallet.reserve_utxo_with_value(utxo_value, |_| false);
    let picked_again = picked_again.expect("must return another outpoint");
    assert_ne!(picked_again, picked, "must pick a different unleased UTXO");
    assert_eq!(remaining_again, 1, "one more left after second pick");
}

#[tokio::test]
#[serial]
async fn reserve_utxo_with_value_filters_by_value() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, general_kp, _) =
        build_operator_wallet(&bitcoind, 7, 8, 3, Amount::from_btc(0.5).unwrap()).await;

    // Seed two pools at different denominations.
    let small_value = Amount::from_btc(0.01).unwrap();
    let large_value = Amount::from_btc(0.05).unwrap();
    for value in [small_value, large_value] {
        let funded = wallet
            .create_reserved_utxos(FeeRate::from_sat_per_vb(5).unwrap(), value, 2)
            .await
            .unwrap_or_else(|e| panic!("seed funding for {value} failed: {e}"));
        let signed = sign_and_finalize(funded.psbt, general_kp);
        bitcoind
            .client
            .send_raw_transaction(&signed)
            .expect("broadcast");
        let miner_addr = bitcoind.client.new_address().expect("miner");
        bitcoind
            .client
            .generate_to_address(1, &miner_addr)
            .expect("mine");
        wallet.sync().await.expect("sync");
    }

    // Looking up by small value returns ONLY the small UTXOs.
    let small_pool = wallet.reserved_utxos_with_value(small_value);
    assert_eq!(small_pool.len(), 2, "expected 2 UTXOs of {small_value}");
    for u in &small_pool {
        assert_eq!(u.amount, small_value);
    }
    let large_pool = wallet.reserved_utxos_with_value(large_value);
    assert_eq!(large_pool.len(), 2, "expected 2 UTXOs of {large_value}");
    for u in &large_pool {
        assert_eq!(u.amount, large_value);
    }
    // Mismatched value yields nothing.
    let missing = wallet.reserved_utxos_with_value(Amount::from_btc(0.99).unwrap());
    assert!(missing.is_empty(), "no UTXOs of unmatched value");
}

#[tokio::test]
#[serial]
async fn sync_prunes_leases_whose_outpoints_have_been_spent() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, general_kp, general_pk) =
        build_operator_wallet(&bitcoind, 9, 10, 2, Amount::from_btc(0.5).unwrap()).await;

    // Lease one of the general-wallet UTXOs (manually — represents some prior funding tx
    // we built but haven't broadcast yet). After the chain spends it from elsewhere
    // (simulated below by broadcasting a tx that consumes it), `sync` should drop the
    // lease.
    let general_utxos: Vec<OutPoint> = wallet
        .general()
        .list_utxos()
        .into_iter()
        .map(|u| u.outpoint)
        .collect();
    let target_outpoint = general_utxos[0];
    wallet.lease(&[target_outpoint]);
    assert!(wallet.leased_outpoints().contains(&target_outpoint));

    // Spend `target_outpoint` directly via a manually-built tx, broadcast it, mine, sync.
    let prevout = wallet
        .general()
        .list_utxos()
        .into_iter()
        .find(|u| u.outpoint == target_outpoint)
        .expect("prevout found");
    let fee = Amount::from_sat(2_000);
    let drain_value = prevout.amount - fee;
    let drain_script =
        Address::p2tr(&Secp256k1::new(), general_pk, None, Network::Regtest).script_pubkey();
    let unsigned_tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version(3),
        lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
        input: vec![bdk_wallet::bitcoin::TxIn {
            previous_output: target_outpoint,
            ..Default::default()
        }],
        output: vec![bdk_wallet::bitcoin::TxOut {
            value: drain_value,
            script_pubkey: drain_script,
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx");
    psbt.inputs[0].witness_utxo = Some(bdk_wallet::bitcoin::TxOut {
        value: prevout.amount,
        script_pubkey: prevout.script_pubkey.clone(),
    });
    let signed = sign_and_finalize(psbt, general_kp);
    bitcoind
        .client
        .send_raw_transaction(&signed)
        .expect("broadcast");
    let miner_addr = bitcoind.client.new_address().expect("miner");
    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine");
    wallet.sync().await.expect("post-spend sync");

    // Sync should have observed `target_outpoint` as spent and pruned its lease.
    assert!(
        !wallet.leased_outpoints().contains(&target_outpoint),
        "sync must prune lease whose outpoint is now spent on-chain"
    );
}

#[tokio::test]
#[serial]
async fn refill_workflow_skips_existing_pool_members() {
    // The composer documents that callers query existing pool size first, then request
    // only the delta. Verify that `create_reserved_utxos` doesn't try to re-spend
    // existing pool members back to themselves (it adds them to the exclude set).
    let bitcoind = setup_bitcoind();
    let (mut wallet, general_kp, _) =
        build_operator_wallet(&bitcoind, 11, 12, 3, Amount::from_btc(0.5).unwrap()).await;

    let utxo_value = Amount::from_btc(0.01).unwrap();
    let fee_rate = FeeRate::from_sat_per_vb(5).unwrap();

    // First batch: seed the pool with 2 UTXOs.
    let first = wallet
        .create_reserved_utxos(fee_rate, utxo_value, 2)
        .await
        .expect("first seed");
    let signed = sign_and_finalize(first.psbt, general_kp);
    bitcoind
        .client
        .send_raw_transaction(&signed)
        .expect("broadcast first");
    let miner_addr = bitcoind.client.new_address().expect("miner");
    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine");
    wallet.sync().await.expect("sync after first");

    let pool_after_first = wallet.reserved_utxos_with_value(utxo_value);
    let pool_outpoints_first: BTreeSet<OutPoint> =
        pool_after_first.iter().map(|u| u.outpoint).collect();
    assert_eq!(pool_after_first.len(), 2);

    // Refill: ask for 2 more. The composer must NOT spend the existing 2 back to itself.
    let refill = wallet
        .create_reserved_utxos(fee_rate, utxo_value, 2)
        .await
        .expect("refill");
    for spent in refill.spent() {
        assert!(
            !pool_outpoints_first.contains(&spent),
            "refill must not spend an existing pool UTXO ({spent})"
        );
    }
    let signed_refill = sign_and_finalize(refill.psbt, general_kp);
    bitcoind
        .client
        .send_raw_transaction(&signed_refill)
        .expect("broadcast refill");
    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine refill");
    wallet.sync().await.expect("sync after refill");

    let pool_after_refill = wallet.reserved_utxos_with_value(utxo_value);
    assert_eq!(
        pool_after_refill.len(),
        4,
        "pool should now contain the original 2 + the 2 we just added"
    );
}
