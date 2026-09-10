#![expect(
    unused_crate_dependencies,
    reason = "this integration-test binary doesn't reference every dev-dependency declared in Cargo.toml; some are pulled in only by the lib's unit tests or other test targets"
)]
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
//! - **Persistence**: a restart from the same stores resumes at the persisted tip and applies only
//!   the chain delta; staged state is committed in bounded batches; a failed commit is retried
//!   without gaps or duplicates; a reorg rolls the persisted chain back; a bootstrap checkpoint
//!   skips history below it.
//!
//! Tests are `#[serial]` because `bitcoind` binds a fixed RPC port — parallel runs would
//! collide. Each test spins up a fresh `bitcoind` so state doesn't leak between cases.
//!
//! Signing of the funded PSBTs (the `create_reserved_utxos` happy path) is performed
//! in-process with the test's known operator privkey: the native general wallet is
//! descriptor-only, so production goes through secret-service. The test bypasses that by
//! signing with the same keypair the descriptor was constructed from (BIP-341 key-path with
//! the empty-merkle-root tap-tweak).

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    num::NonZeroU32,
    path::Path,
    sync::Arc,
};

use bdk_bitcoind_rpc::bitcoincore_rpc::{json::CreateRawTransactionInput, RpcApi};
use bdk_wallet::{
    bitcoin::{
        hashes::Hash,
        key::{Keypair, Secp256k1, TapTweak},
        secp256k1::{Message, SecretKey},
        sighash::{Prevouts, SighashCache},
        taproot, Address, Amount, BlockHash, FeeRate, Network, OutPoint, Psbt, TapSighashType,
        Transaction, Txid, Witness, XOnlyPublicKey,
    },
    chain::{BlockId, Merge},
    descriptor, ChangeSet,
};
use corepc_node::{Conf, Node};
use operator_wallet::{
    load_or_create, sync::Backend, test_utils::MemoryStore, Error as OperatorWalletError,
    GeneralUtxoPolicy, GeneralWallet, InitError, NativeGeneralWallet, OperatorWallet,
    OperatorWalletConfig, SqliteStore, WalletKind, DEFAULT_PERSIST_EVERY_BLOCKS,
};
use serial_test::serial;

/// The concrete wallet type under test: native general wallet + in-memory stores.
type TestWallet = OperatorWallet<NativeGeneralWallet<MemoryStore>, MemoryStore>;

/// The production shape: native general wallet + one SQLite file per wallet.
type SqliteWallet = OperatorWallet<NativeGeneralWallet<SqliteStore>, SqliteStore>;

/// The pair of in-memory stores backing one operator wallet. Clones share storage, so keeping a
/// `Stores` around and re-opening from it simulates a process restart.
#[derive(Clone, Default)]
struct Stores {
    general: MemoryStore,
    reserved: MemoryStore,
}

/// 1 sat — the smallest possible "anchor" value, used in tests where we don't actually
/// want any UTXO to look like an anchor. `OperatorWallet`'s anchor exclusion filters on
/// (value == cpfp_value) AND (confirmations == 0); none of the test outputs are that small
/// AND unconfirmed-at-query-time, so the filter is a no-op in these tests.
const SENTINEL_ANCHOR_VALUE: Amount = Amount::from_sat(330);

/// Boots a fresh regtest `bitcoind`, mines coinbase maturity, and returns the node.
fn setup_bitcoind() -> Node {
    let mut conf = Conf::default();
    conf.args.push("-txindex=1");
    let bitcoind = Node::with_conf("bitcoind", &conf).expect("bitcoind must start");
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

/// Opens (loads or creates) an operator wallet against `stores` without funding or syncing it.
/// Returns the wallet plus the origin reported for the general and reserved wallets.
async fn open_wallet(
    bitcoind: &Node,
    general_seed: u8,
    reserved_seed: u8,
    stores: &Stores,
    bootstrap_checkpoint: Option<BlockId>,
    persist_every_blocks: NonZeroU32,
) -> TestWallet {
    let (_, general_pubkey) = keypair_from_seed(general_seed);
    let (_, reserved_pubkey) = keypair_from_seed(reserved_seed);

    let general_backend = Backend::BitcoinCore(Arc::new(sync_rpc_client(bitcoind)));
    let reserved_backend = Backend::BitcoinCore(Arc::new(sync_rpc_client(bitcoind)));
    let config = OperatorWalletConfig::new(SENTINEL_ANCHOR_VALUE, Network::Regtest)
        .with_persist_every_blocks(persist_every_blocks);
    let general = NativeGeneralWallet::load_or_create(
        general_pubkey,
        &config,
        general_backend,
        stores.general.clone(),
        bootstrap_checkpoint,
    )
    .await
    .expect("general wallet init");
    let wallet = OperatorWallet::load_or_create(
        general,
        reserved_pubkey,
        config,
        reserved_backend,
        stores.reserved.clone(),
        bootstrap_checkpoint,
        BTreeSet::new(),
    )
    .await
    .expect("reserved wallet init");
    wallet
}

/// Builds a fully-wired [`TestWallet`] against fresh in-memory stores. Funds the general wallet
/// with `general_funding_utxos` UTXOs of `general_funding_value` each via bitcoind's own wallet,
/// then syncs. The reserved wallet is created from a separate deterministic keypair and starts
/// empty.
async fn build_operator_wallet(
    bitcoind: &Node,
    general_seed: u8,
    reserved_seed: u8,
    general_funding_utxos: usize,
    general_funding_value: Amount,
) -> (
    TestWallet,
    Keypair, // general keypair, used by the test to sign funded PSBTs
    XOnlyPublicKey,
) {
    let (general_kp, general_pubkey) = keypair_from_seed(general_seed);
    let mut wallet = open_wallet(
        bitcoind,
        general_seed,
        reserved_seed,
        &Stores::default(),
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;

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
        .create_reserved_utxos(
            fee_rate,
            utxo_value,
            quantity,
            GeneralUtxoPolicy::IncludeUnconfirmed,
        )
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
async fn create_reserved_utxos_reports_only_unconfirmed_general_utxos() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, _, general_pubkey) =
        build_operator_wallet(&bitcoind, 13, 14, 0, Amount::ZERO).await;

    let unconfirmed_amount = Amount::from_btc(1.0).unwrap();
    let general_address = Address::p2tr(&Secp256k1::new(), general_pubkey, None, Network::Regtest);
    bitcoind
        .client
        .send_to_address(&general_address, unconfirmed_amount)
        .expect("send unconfirmed funds");
    wallet.sync().await.expect("sync unconfirmed deposit");

    let general_utxos = wallet.general().list_utxos();
    assert_eq!(general_utxos.len(), 1, "one general-wallet UTXO");
    assert_eq!(
        general_utxos[0].confirmations, 0,
        "deposit must be unconfirmed"
    );

    let err = wallet
        .create_reserved_utxos(
            FeeRate::from_sat_per_vb(5).unwrap(),
            Amount::from_btc(0.01).unwrap(),
            1,
            GeneralUtxoPolicy::ConfirmedOnly,
        )
        .await
        .expect_err("unconfirmed general-wallet funds must not be selected");

    match err {
        OperatorWalletError::NoConfirmedGeneralUtxos {
            unconfirmed_count,
            unconfirmed_amount: actual_amount,
        } => {
            assert_eq!(unconfirmed_count, 1);
            assert_eq!(actual_amount, unconfirmed_amount);
        }
        other => panic!("expected no-confirmed-UTXO error, got {other:?}"),
    }
    assert!(
        wallet.leased_outpoints().is_empty(),
        "failed refill must not lease the unconfirmed UTXO"
    );
}

#[tokio::test]
#[serial]
async fn create_reserved_utxos_can_include_unconfirmed_general_utxos_when_allowed() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, _, general_pubkey) =
        build_operator_wallet(&bitcoind, 15, 16, 0, Amount::ZERO).await;

    let unconfirmed_amount = Amount::from_btc(1.0).unwrap();
    let general_address = Address::p2tr(&Secp256k1::new(), general_pubkey, None, Network::Regtest);
    bitcoind
        .client
        .send_to_address(&general_address, unconfirmed_amount)
        .expect("send unconfirmed funds");
    wallet.sync().await.expect("sync unconfirmed deposit");

    let unconfirmed_outpoint = wallet.general().list_utxos()[0].outpoint;
    let funded = wallet
        .create_reserved_utxos(
            FeeRate::from_sat_per_vb(5).unwrap(),
            Amount::from_btc(0.01).unwrap(),
            1,
            GeneralUtxoPolicy::IncludeUnconfirmed,
        )
        .await
        .expect("unconfirmed general-wallet funds may be selected when allowed");

    assert!(
        funded.spent().contains(&unconfirmed_outpoint),
        "funding transaction should spend the unconfirmed general-wallet UTXO"
    );
    assert!(
        wallet.leased_outpoints().contains(&unconfirmed_outpoint),
        "selected unconfirmed UTXO must be leased"
    );
}

#[tokio::test]
#[serial]
async fn create_reserved_utxos_excludes_unconfirmed_when_confirmed_funds_are_available() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, _, general_pubkey) =
        build_operator_wallet(&bitcoind, 17, 18, 1, Amount::from_btc(1.0).unwrap()).await;

    let confirmed_outpoint = wallet.general().list_utxos()[0].outpoint;
    let general_address = Address::p2tr(&Secp256k1::new(), general_pubkey, None, Network::Regtest);
    bitcoind
        .client
        .send_to_address(&general_address, Amount::from_btc(0.5).unwrap())
        .expect("send unconfirmed funds");
    wallet.sync().await.expect("sync mixed funds");

    let unconfirmed_outpoint = wallet
        .general()
        .list_utxos()
        .into_iter()
        .find(|utxo| utxo.confirmations == 0)
        .expect("unconfirmed UTXO")
        .outpoint;
    let funded = wallet
        .create_reserved_utxos(
            FeeRate::from_sat_per_vb(5).unwrap(),
            Amount::from_btc(0.01).unwrap(),
            1,
            GeneralUtxoPolicy::ConfirmedOnly,
        )
        .await
        .expect("confirmed funds should fund reserved UTXOs");

    assert!(
        funded.spent().contains(&confirmed_outpoint),
        "funding transaction should spend the confirmed UTXO"
    );
    assert!(
        !funded.spent().contains(&unconfirmed_outpoint),
        "funding transaction must exclude the unconfirmed UTXO"
    );
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
        .create_reserved_utxos(
            FeeRate::from_sat_per_vb(5).unwrap(),
            utxo_value,
            3,
            GeneralUtxoPolicy::IncludeUnconfirmed,
        )
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
            .create_reserved_utxos(
                FeeRate::from_sat_per_vb(5).unwrap(),
                value,
                2,
                GeneralUtxoPolicy::IncludeUnconfirmed,
            )
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
        .create_reserved_utxos(
            fee_rate,
            utxo_value,
            2,
            GeneralUtxoPolicy::IncludeUnconfirmed,
        )
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
        .create_reserved_utxos(
            fee_rate,
            utxo_value,
            2,
            GeneralUtxoPolicy::IncludeUnconfirmed,
        )
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

// ── Persistence ────────────────────────────────────────────────────────────

/// Every block height mentioned (added or removed) across `changesets`.
fn chain_heights(changesets: &[ChangeSet]) -> BTreeSet<u32> {
    changesets
        .iter()
        .flat_map(|cs| cs.local_chain.blocks.keys().copied())
        .collect()
}

/// Merges `changesets` in order into one, the way a store's aggregate view would.
fn merged(changesets: &[ChangeSet]) -> ChangeSet {
    let mut out = ChangeSet::default();
    for cs in changesets {
        out.merge(cs.clone());
    }
    out
}

/// Heights whose value is `Some` in the aggregate, i.e. blocks a restart would load.
fn live_heights(aggregate: &ChangeSet) -> BTreeMap<u32, BlockHash> {
    aggregate
        .local_chain
        .blocks
        .iter()
        .filter_map(|(h, hash)| hash.map(|hash| (*h, hash)))
        .collect()
}

fn mine(bitcoind: &Node, n: usize) {
    let addr = bitcoind.client.new_address().expect("miner address");
    bitcoind
        .client
        .generate_to_address(n, &addr)
        .expect("mine blocks");
}

#[tokio::test]
#[serial]
async fn restart_loads_persisted_state_and_applies_only_the_chain_delta() {
    let bitcoind = setup_bitcoind();
    let stores = Stores::default();
    let mut wallet = open_wallet(
        &bitcoind,
        21,
        22,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    for store in [&stores.general, &stores.reserved] {
        assert_eq!(
            store.history().len(),
            1,
            "a fresh store gets exactly the create commit"
        );
    }

    // Fund the general wallet so there is transaction-graph state to carry across the restart.
    let (_, general_pubkey) = keypair_from_seed(21);
    let general_address = Address::p2tr(&Secp256k1::new(), general_pubkey, None, Network::Regtest);
    bitcoind
        .client
        .send_to_address(&general_address, Amount::from_btc(0.5).unwrap())
        .expect("fund general wallet");
    mine(&bitcoind, 1);
    wallet.sync().await.expect("initial sync");

    let tip_before = wallet.local_chain_tip_height();
    let utxos_before: BTreeSet<OutPoint> = wallet
        .general()
        .list_utxos()
        .into_iter()
        .map(|u| u.outpoint)
        .collect();
    assert_eq!(utxos_before.len(), 1, "general wallet sees its funding");
    let general_history_len = stores.general.history().len();
    let reserved_history_len = stores.reserved.history().len();
    drop(wallet);

    // The chain moves on while the node is "down".
    mine(&bitcoind, 5);

    let mut wallet = open_wallet(
        &bitcoind,
        21,
        22,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    assert_eq!(
        stores.general.history().len(),
        general_history_len,
        "loading writes nothing"
    );
    assert_eq!(stores.reserved.history().len(), reserved_history_len);
    assert_eq!(
        wallet.local_chain_tip_height(),
        tip_before,
        "loaded wallet resumes at the persisted tip before syncing"
    );
    let utxos_after_load: BTreeSet<OutPoint> = wallet
        .general()
        .list_utxos()
        .into_iter()
        .map(|u| u.outpoint)
        .collect();
    assert_eq!(
        utxos_after_load, utxos_before,
        "transaction-graph state survives the restart"
    );

    wallet.sync().await.expect("post-restart sync");
    assert_eq!(wallet.local_chain_tip_height(), tip_before + 5);

    // Only the five new blocks were applied after the restart: no persisted changeset touches a
    // height at or below the old tip.
    let expected: BTreeSet<u32> = (tip_before + 1..=tip_before + 5).collect();
    let general_new = &stores.general.history()[general_history_len..];
    let reserved_new = &stores.reserved.history()[reserved_history_len..];
    assert_eq!(chain_heights(general_new), expected);
    assert_eq!(chain_heights(reserved_new), expected);
}

#[tokio::test]
#[serial]
async fn sync_commits_in_batches_bounded_by_the_cadence() {
    let bitcoind = setup_bitcoind(); // 101 blocks
    let stores = Stores::default();
    let cadence = NonZeroU32::new(25).unwrap();
    let mut wallet = open_wallet(&bitcoind, 23, 24, &stores, None, cadence).await;
    wallet.sync().await.expect("sync");
    let tip = wallet.local_chain_tip_height();
    assert_eq!(tip, 101);

    for store in [&stores.general, &stores.reserved] {
        let history = store.history();
        // First entry is the create-time changeset (descriptor, network, genesis block).
        assert!(history[0].descriptor.is_some());
        assert_eq!(history[0].local_chain.blocks.len(), 1);
        for cs in &history[1..] {
            assert!(
                cs.local_chain.blocks.len() <= cadence.get() as usize,
                "a batch must never exceed the cadence: {} blocks",
                cs.local_chain.blocks.len()
            );
        }
        let min_batches = (tip / cadence) as usize;
        assert!(
            history.len() > min_batches,
            "expected the create commit plus at least {min_batches} batch commits, got {}",
            history.len()
        );
        let all: BTreeSet<u32> = (0..=tip).collect();
        assert_eq!(
            chain_heights(&history),
            all,
            "every height committed exactly once overall"
        );
        assert_eq!(live_heights(&store.aggregate()).len(), all.len());
    }
}

#[tokio::test]
#[serial]
async fn failed_commit_aborts_the_attempt_and_the_retry_leaves_no_gaps() {
    let bitcoind = setup_bitcoind(); // 101 blocks
    let (_, pubkey) = keypair_from_seed(25);
    let (desc, ..) = descriptor!(tr(pubkey)).expect("descriptor");
    let mut store = MemoryStore::new();
    let mut wallet = load_or_create(&mut store, desc, Network::Regtest, None)
        .await
        .expect("create");
    assert_eq!(store.persist_calls(), 1, "create persists once");

    let cadence = NonZeroU32::new(25).unwrap();
    // Call 1 was the create; call 2 is the batch ending at height 25; call 3 (height 50) fails.
    store.fail_on_persist_call(3);
    let backend = Backend::BitcoinCore(Arc::new(sync_rpc_client(&bitcoind)));

    backend
        .sync_wallet(&mut wallet, &mut store, cadence)
        .await
        .expect_err("injected persist failure must abort the attempt");
    assert_eq!(
        wallet.latest_checkpoint().height(),
        50,
        "applied up to the failed batch"
    );
    assert!(wallet.staged().is_some(), "failed batch stays staged");
    let persisted_tip = *live_heights(&store.aggregate()).keys().last().unwrap();
    assert_eq!(persisted_tip, 25, "only the successful batch is durable");

    backend
        .sync_wallet(&mut wallet, &mut store, cadence)
        .await
        .expect("retry succeeds");
    assert!(
        wallet.staged().is_none(),
        "everything drained after a clean attempt"
    );
    let live = live_heights(&store.aggregate());
    let expected: BTreeSet<u32> = (0..=101).collect();
    assert_eq!(
        live.keys().copied().collect::<BTreeSet<_>>(),
        expected,
        "no gaps"
    );
    assert_eq!(wallet.latest_checkpoint().height(), 101);
    for (height, hash) in &live {
        assert_eq!(
            wallet.latest_checkpoint().get(*height).map(|cp| cp.hash()),
            Some(*hash),
            "persisted hash matches the wallet's chain at {height}"
        );
    }
}

#[tokio::test]
#[serial]
async fn reorg_rolls_back_the_persisted_chain_and_reanchors_reserved_utxos() {
    let bitcoind = setup_bitcoind(); // 101 blocks
    let stores = Stores::default();
    let mut wallet = open_wallet(
        &bitcoind,
        27,
        28,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    let rpc = sync_rpc_client(&bitcoind);

    // Fund the reserved wallet directly and confirm it at height 102.
    let value = Amount::from_btc(0.01).unwrap();
    let reserved_addr = Address::from_script(&wallet.reserved_script_pubkey(), Network::Regtest)
        .expect("reserved address");
    bitcoind
        .client
        .send_to_address(&reserved_addr, value)
        .expect("fund reserved");
    mine(&bitcoind, 3); // heights 102, 103, 104
    wallet.sync().await.expect("sync");
    assert_eq!(wallet.local_chain_tip_height(), 104);
    let pool = wallet.reserved_utxos_with_value(value);
    assert_eq!(pool.len(), 1);
    assert_eq!(pool[0].confirmations, 3, "confirmed at 102, tip 104");
    let reserved_history_len = stores.reserved.history().len();

    // Reorg out 102..=104 and mine a single replacement block at 102. The funding tx returns to
    // the mempool and is re-mined into the replacement block.
    let old_102 = rpc.get_block_hash(102).expect("hash 102");
    rpc.invalidate_block(&old_102).expect("invalidate");
    mine(&bitcoind, 1);
    let new_102 = rpc.get_block_hash(102).expect("new hash 102");
    assert_ne!(new_102, old_102);

    wallet.sync().await.expect("sync after reorg");
    assert_eq!(wallet.local_chain_tip_height(), 102);
    assert_eq!(wallet.reserved_tip_hash(), new_102);
    let pool = wallet.reserved_utxos_with_value(value);
    assert_eq!(pool.len(), 1, "the UTXO is still ours");
    assert_eq!(
        pool[0].confirmations, 1,
        "re-anchored in the replacement block"
    );

    // The persisted rollback: 102 replaced, 103 and 104 removed.
    let after = merged(&stores.reserved.history()[reserved_history_len..]);
    assert_eq!(after.local_chain.blocks.get(&102), Some(&Some(new_102)));
    assert_eq!(after.local_chain.blocks.get(&103), Some(&None));
    assert_eq!(after.local_chain.blocks.get(&104), Some(&None));

    // A restart from the stores lands on the new branch.
    drop(wallet);
    let wallet = open_wallet(
        &bitcoind,
        27,
        28,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    assert_eq!(wallet.local_chain_tip_height(), 102);
    assert_eq!(wallet.reserved_tip_hash(), new_102);
    assert_eq!(wallet.reserved_utxos_with_value(value).len(), 1);
}

#[tokio::test]
#[serial]
async fn an_unconfirmed_payment_is_not_spendable_after_a_restart() {
    let bitcoind = setup_bitcoind();
    let stores = Stores::default();
    let mut wallet = open_wallet(
        &bitcoind,
        33,
        34,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    wallet.sync().await.expect("initial sync");

    // A payment to the reserved script that later leaves the mempool cannot be evicted from the
    // wallet with this BDK version, so its mempool timestamp is kept in memory only.
    let value = Amount::from_btc(0.01).unwrap();
    let reserved_addr = Address::from_script(&wallet.reserved_script_pubkey(), Network::Regtest)
        .expect("reserved address");
    bitcoind
        .client
        .send_to_address(&reserved_addr, value)
        .expect("send to reserved script");
    wallet
        .sync()
        .await
        .expect("sync with the payment in the mempool");

    let pool = wallet.reserved_utxos_with_value(value);
    assert_eq!(pool.len(), 1, "unconfirmed payment visible in memory");
    assert_eq!(pool[0].confirmations, 0);
    let txid = pool[0].outpoint.txid;

    // Nothing about it reaches the store, so repeated payments that never confirm cannot grow it.
    let aggregate = stores.reserved.aggregate();
    assert!(
        !aggregate
            .tx_graph
            .txs
            .iter()
            .any(|tx| tx.compute_txid() == txid),
        "an unconfirmed transaction must not be persisted"
    );
    assert!(
        aggregate.tx_graph.last_seen.is_empty(),
        "mempool timestamps must not be persisted"
    );

    // So a restart cannot hand the payment out as a pool member.
    drop(wallet);
    let wallet = open_wallet(
        &bitcoind,
        33,
        34,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    assert!(
        wallet.reserved_utxos_with_value(value).is_empty(),
        "an unconfirmed payment must not be spendable after a restart"
    );
    assert!(
        stores.reserved.aggregate().tx_graph.txs.is_empty(),
        "the store holds no unanchored transactions"
    );
}

#[tokio::test]
#[serial]
async fn a_payment_seen_in_the_mempool_survives_confirmation_and_restart() {
    let bitcoind = setup_bitcoind();
    let stores = Stores::default();
    let mut wallet = open_wallet(
        &bitcoind,
        35,
        36,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    wallet.sync().await.expect("initial sync");

    let value = Amount::from_btc(0.02).unwrap();
    let reserved_addr = Address::from_script(&wallet.reserved_script_pubkey(), Network::Regtest)
        .expect("reserved address");
    bitcoind
        .client
        .send_to_address(&reserved_addr, value)
        .expect("send to reserved script");

    // Seen unconfirmed first, then confirmed: applying the block stages only the anchor, because
    // the transaction is already in the wallet's graph.
    wallet
        .sync()
        .await
        .expect("sync with the payment in the mempool");
    mine(&bitcoind, 1);
    wallet
        .sync()
        .await
        .expect("sync with the payment confirmed");
    let pool = wallet.reserved_utxos_with_value(value);
    assert_eq!(pool.len(), 1);
    assert_eq!(pool[0].confirmations, 1);

    drop(wallet);
    let wallet = open_wallet(
        &bitcoind,
        35,
        36,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    let pool = wallet.reserved_utxos_with_value(value);
    assert_eq!(
        pool.len(),
        1,
        "a confirmed payment first seen in the mempool must survive a restart"
    );
    assert!(pool[0].confirmations >= 1);
}

/// Spends `txid`'s first input again, paying the node's own wallet a much higher fee, so `txid` is
/// replaced and leaves the mempool. `txid` must not be confirmed.
fn replace(bitcoind: &Node, rpc: &bdk_bitcoind_rpc::bitcoincore_rpc::Client, txid: Txid) {
    let input = rpc
        .get_raw_transaction_info(&txid, None)
        .expect("tx info")
        .vin[0]
        .clone();
    let spent = OutPoint {
        txid: input.txid.expect("input txid"),
        vout: input.vout.expect("input vout"),
    };
    let value = rpc
        .get_raw_transaction_info(&spent.txid, None)
        .expect("input tx info")
        .vout[spent.vout as usize]
        .value;
    let sink = bitcoind.client.new_address().expect("sink address");
    let outputs = HashMap::from([(
        sink.to_string(),
        value - Amount::from_btc(0.001).expect("fee"),
    )]);
    let conflicting = rpc
        .create_raw_transaction(
            &[CreateRawTransactionInput {
                txid: spent.txid,
                vout: spent.vout,
                sequence: None,
            }],
            &outputs,
            None,
            None,
        )
        .expect("build conflicting tx");
    let signed = rpc
        .sign_raw_transaction_with_wallet(&conflicting, None, None)
        .expect("sign")
        .transaction()
        .expect("signed tx");
    rpc.send_raw_transaction(&signed).expect("replace");
}

#[tokio::test]
#[serial]
async fn a_reorged_out_payment_stops_being_spendable() {
    let bitcoind = setup_bitcoind();
    let stores = Stores::default();
    let mut wallet = open_wallet(
        &bitcoind,
        37,
        38,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    let rpc = sync_rpc_client(&bitcoind);
    wallet.sync().await.expect("initial sync");

    // Confirm a payment to the reserved script.
    let value = Amount::from_btc(0.03).unwrap();
    let reserved_addr = Address::from_script(&wallet.reserved_script_pubkey(), Network::Regtest)
        .expect("reserved address");
    bitcoind
        .client
        .send_to_address(&reserved_addr, value)
        .expect("send to reserved script");
    mine(&bitcoind, 1);
    wallet
        .sync()
        .await
        .expect("sync with the payment confirmed");
    let pool = wallet.reserved_utxos_with_value(value);
    assert_eq!(pool.len(), 1, "payment confirmed and visible");

    // Take the block back out and double-spend the payment's input, so it ends up neither in the
    // chain nor in the mempool.
    let height = rpc.get_block_count().expect("block count");
    rpc.invalidate_block(&rpc.get_block_hash(height).expect("block hash"))
        .expect("invalidate");
    replace(&bitcoind, &rpc, pool[0].outpoint.txid);
    mine(&bitcoind, 2);

    wallet.sync().await.expect("sync after the reorg");
    assert!(
        wallet.reserved_utxos_with_value(value).is_empty(),
        "a reorged-out payment must not stay spendable"
    );

    drop(wallet);
    let wallet = open_wallet(
        &bitcoind,
        37,
        38,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    assert!(
        wallet.reserved_utxos_with_value(value).is_empty(),
        "and must not come back after a restart"
    );
}

#[tokio::test]
#[serial]
async fn a_store_ahead_of_the_node_is_refused() {
    let bitcoind = setup_bitcoind();
    let stores = Stores::default();
    let mut wallet = open_wallet(
        &bitcoind,
        39,
        40,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    wallet.sync().await.expect("sync");
    let tip = wallet.local_chain_tip_height();
    assert!(tip > 0);
    drop(wallet);

    // Roll the node back below the persisted tip, as restoring an older data directory would.
    let rpc = sync_rpc_client(&bitcoind);
    rpc.invalidate_block(&rpc.get_block_hash(u64::from(tip) - 2).expect("block hash"))
        .expect("invalidate");
    assert!(rpc.get_block_count().expect("count") < u64::from(tip));

    let (_, general_pubkey) = keypair_from_seed(39);
    let err = NativeGeneralWallet::load_or_create(
        general_pubkey,
        &OperatorWalletConfig::new(SENTINEL_ANCHOR_VALUE, Network::Regtest),
        Backend::BitcoinCore(Arc::new(sync_rpc_client(&bitcoind))),
        stores.general.clone(),
        None,
    )
    .await
    .expect_err("a store ahead of the node must be refused");
    assert!(
        matches!(err, InitError::BackendBehindTip { tip: stored, .. } if stored == tip),
        "got {err:?}"
    );
}

#[tokio::test]
#[serial]
async fn a_lease_survives_its_funding_leaving_the_mempool() {
    let bitcoind = setup_bitcoind();
    let stores = Stores::default();
    let mut wallet = open_wallet(
        &bitcoind,
        43,
        44,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    let rpc = sync_rpc_client(&bitcoind);
    wallet.sync().await.expect("initial sync");

    // An unconfirmed payment to the reserved script, leased as the claim-funding path would.
    let value = Amount::from_btc(0.04).unwrap();
    let reserved_addr = Address::from_script(&wallet.reserved_script_pubkey(), Network::Regtest)
        .expect("reserved address");
    bitcoind
        .client
        .send_to_address(&reserved_addr, value)
        .expect("send to reserved script");
    wallet.sync().await.expect("sync with the payment pending");
    let leased = wallet
        .reserve_utxo_with_value(value, |_| false)
        .0
        .expect("an unconfirmed pool member is reservable");
    assert!(wallet.leased_outpoints().contains(&leased));

    // The payment leaves the mempool, so it is no longer spendable, but nothing has spent it.
    replace(&bitcoind, &rpc, leased.txid);
    wallet.sync().await.expect("sync with the payment gone");
    assert!(
        wallet.reserved_utxos_with_value(value).is_empty(),
        "gone from the mempool, so not offered for spending"
    );
    assert!(
        wallet.leased_outpoints().contains(&leased),
        "but the lease must hold: another graph must not be handed the same outpoint"
    );
}

#[tokio::test]
#[serial]
async fn a_reorg_across_a_restart_reconciles() {
    let bitcoind = setup_bitcoind();
    let stores = Stores::default();
    let mut wallet = open_wallet(
        &bitcoind,
        41,
        42,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    wallet.sync().await.expect("sync");
    let tip = wallet.local_chain_tip_height();
    let tip_hash = wallet.reserved_tip_hash();
    drop(wallet);

    // While stopped, the stored tip is reorged away and the node builds past it.
    let rpc = sync_rpc_client(&bitcoind);
    rpc.invalidate_block(&rpc.get_block_hash(u64::from(tip)).expect("block hash"))
        .expect("invalidate");
    mine(&bitcoind, 2);
    assert_ne!(
        rpc.get_block_hash(u64::from(tip)).expect("new hash"),
        tip_hash,
        "the stored tip's block is gone"
    );

    // The node is no shorter than the store, so the emitter can reconcile and startup proceeds.
    let mut wallet = open_wallet(
        &bitcoind,
        41,
        42,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    wallet.sync().await.expect("sync after the reorg");
    assert_eq!(wallet.local_chain_tip_height(), tip + 1);
    assert_ne!(wallet.reserved_tip_hash(), tip_hash);
}

#[tokio::test]
#[serial]
async fn bootstrap_checkpoint_skips_history_below_it() {
    let bitcoind = setup_bitcoind(); // 101 blocks
    let rpc = sync_rpc_client(&bitcoind);
    let checkpoint = BlockId {
        height: 90,
        hash: rpc.get_block_hash(90).expect("hash 90"),
    };
    let stores = Stores::default();
    let mut wallet = open_wallet(
        &bitcoind,
        29,
        30,
        &stores,
        Some(checkpoint),
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    assert_eq!(
        wallet.local_chain_tip_height(),
        90,
        "fresh wallet starts at the checkpoint"
    );
    // One create-time commit carrying descriptor, network, genesis and the checkpoint.
    let created = stores.reserved.history();
    assert_eq!(created.len(), 1, "wallet and checkpoint commit together");
    assert_eq!(chain_heights(&created), BTreeSet::from([0, 90]));

    wallet.sync().await.expect("sync");
    assert_eq!(wallet.local_chain_tip_height(), 101);
    let synced = &stores.reserved.history()[created.len()..];
    let expected: BTreeSet<u32> = (91..=101).collect();
    assert_eq!(
        chain_heights(synced),
        expected,
        "only blocks above the checkpoint are fetched and committed"
    );
    let live = live_heights(&stores.reserved.aggregate());
    assert!(
        (1..90).all(|h| !live.contains_key(&h)),
        "history below the checkpoint is never persisted"
    );
}

/// Opens (loads or creates) a [`SqliteWallet`] whose two stores live in `data_dir`.
async fn open_sqlite_wallet(
    bitcoind: &Node,
    general_seed: u8,
    reserved_seed: u8,
    data_dir: &Path,
) -> SqliteWallet {
    let (_, general_pubkey) = keypair_from_seed(general_seed);
    let (_, reserved_pubkey) = keypair_from_seed(reserved_seed);
    let general_store =
        SqliteStore::open_in_dir(data_dir, WalletKind::General).expect("open general");
    let reserved_store =
        SqliteStore::open_in_dir(data_dir, WalletKind::Reserved).expect("open reserved");
    let config = OperatorWalletConfig::new(SENTINEL_ANCHOR_VALUE, Network::Regtest);
    let general = NativeGeneralWallet::load_or_create(
        general_pubkey,
        &config,
        Backend::BitcoinCore(Arc::new(sync_rpc_client(bitcoind))),
        general_store,
        None,
    )
    .await
    .expect("general wallet init");
    let wallet = OperatorWallet::load_or_create(
        general,
        reserved_pubkey,
        config,
        Backend::BitcoinCore(Arc::new(sync_rpc_client(bitcoind))),
        reserved_store,
        None,
        BTreeSet::new(),
    )
    .await
    .expect("reserved wallet init");
    wallet
}

#[tokio::test]
#[serial]
async fn sqlite_store_survives_a_restart_and_resumes_at_the_persisted_tip() {
    let bitcoind = setup_bitcoind();
    let data_dir = tempfile::tempdir().expect("temp dir");
    let mut wallet = open_sqlite_wallet(&bitcoind, 31, 32, data_dir.path()).await;
    assert!(WalletKind::General.path_in(data_dir.path()).exists());
    assert!(WalletKind::Reserved.path_in(data_dir.path()).exists());

    let (_, general_pubkey) = keypair_from_seed(31);
    let general_address = Address::p2tr(&Secp256k1::new(), general_pubkey, None, Network::Regtest);
    bitcoind
        .client
        .send_to_address(&general_address, Amount::from_btc(0.5).unwrap())
        .expect("fund general wallet");
    mine(&bitcoind, 1);
    wallet.sync().await.expect("initial sync");
    let tip_before = wallet.local_chain_tip_height();
    let utxos_before: BTreeSet<OutPoint> = wallet
        .general()
        .list_utxos()
        .into_iter()
        .map(|u| u.outpoint)
        .collect();
    assert_eq!(utxos_before.len(), 1);
    drop(wallet); // closes both SQLite connections, as a process exit would

    mine(&bitcoind, 5);

    let mut wallet = open_sqlite_wallet(&bitcoind, 31, 32, data_dir.path()).await;
    // Reopening a populated store can only succeed by loading: the create path would fail with
    // `DataAlreadyExists`. The tip proves which state was loaded.
    assert_eq!(
        wallet.local_chain_tip_height(),
        tip_before,
        "resumes at persisted tip"
    );
    let utxos_after_load: BTreeSet<OutPoint> = wallet
        .general()
        .list_utxos()
        .into_iter()
        .map(|u| u.outpoint)
        .collect();
    assert_eq!(
        utxos_after_load, utxos_before,
        "graph state reloaded from SQLite"
    );

    wallet.sync().await.expect("post-restart sync");
    assert_eq!(wallet.local_chain_tip_height(), tip_before + 5);
}
