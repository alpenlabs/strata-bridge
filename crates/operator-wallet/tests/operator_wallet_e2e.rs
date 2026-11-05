#![expect(
    unused_crate_dependencies,
    reason = "this integration-test binary doesn't reference every dev-dependency declared in Cargo.toml; some are pulled in only by the lib's unit tests or other test targets"
)]
//! Crate-level integration tests for `operator-wallet` against a real `bitcoind` regtest
//! node (via `corepc-node`).
//!
//! These tests cover the load-bearing surface of [`OperatorWallet`]:
//!
//! - **Lease bookkeeping**: a committed lease holds its outpoints until an explicit release.
//! - **Reserved-UTXO creation** funds the reserved wallet with the requested denomination +
//!   quantity, and the resulting UTXOs are discoverable via `reserved_utxos_with_value`.
//! - **Pool refill** semantics: caller computes batch size from current count, requests only the
//!   delta, and the wallet doesn't re-spend existing pool members back to itself.
//! - **Sync prunes stale leases** so a long-running operator doesn't accumulate leases for
//!   outpoints that the chain has already spent.
//! - **Persistence**: a restart from the same stores resumes at the persisted tip and applies only
//!   the chain delta; staged state is committed in bounded batches; a failed commit is retried
//!   without gaps or duplicates; a reorg rolls the persisted chain back; a bootstrap checkpoint
//!   skips history below it; a pruned node must still hold the seed block or the sync fails.
//!
//! Tests are `#[serial]` because `bitcoind` binds a fixed RPC port — parallel runs would
//! collide. Each test spins up a fresh `bitcoind` so state doesn't leak between cases.
//!
//! Signing of the funded PSBTs (the `create_reserved_utxos` happy path) is performed
//! in-process with the test's known operator privkey: the general wallet is
//! descriptor-only, so production goes through secret-service. The test bypasses that by
//! signing with the same keypair the descriptor was constructed from (BIP-341 key-path with
//! the empty-merkle-root tap-tweak).

use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    num::NonZeroU32,
    path::Path,
    sync::Arc,
    time::Duration,
};

use bdk_bitcoind_rpc::bitcoincore_rpc::{
    json::CreateRawTransactionInput, jsonrpc::serde_json::Value, RpcApi,
};
use bdk_wallet::{
    bitcoin::{
        absolute::LockTime,
        consensus::encode::serialize_hex,
        hashes::Hash,
        key::{Keypair, Secp256k1, TapTweak},
        secp256k1::{Message, SecretKey},
        sighash::{Prevouts, SighashCache},
        taproot,
        transaction::Version,
        Address, Amount, BlockHash, FeeRate, Network, OutPoint, Psbt, ScriptBuf, Sequence,
        TapSighashType, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey,
    },
    chain::{BlockId, Merge},
    descriptor, ChangeSet,
};
use corepc_node::{Conf, Node};
use operator_wallet::{
    load_or_create,
    sync::Backend,
    test_utils::{MemoryStore, MemoryStoreError},
    Error as OperatorWalletError, GeneralCustody, GeneralUtxoPolicy, InitError, LeaseOwner,
    OperatorWallet, OperatorWalletConfig, PriorChild, ReplacedChild, SqliteStore, WalletKind,
    DEFAULT_PERSIST_EVERY_BLOCKS,
};
use serial_test::serial;
use strata_bridge_primitives::cpfp::ChildSpend;

/// The pair of in-memory stores backing one operator wallet. Clones share storage, so keeping a
/// `Stores` around and re-opening from it simulates a process restart.
#[derive(Clone, Default)]
struct Stores {
    general: MemoryStore,
    reserved: MemoryStore,
}

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

/// Boots a manually prunable regtest `bitcoind`. `-fastprune` shrinks block files to 64 KiB so a
/// few hundred empty blocks span several files and `pruneblockchain` has whole files to delete.
fn setup_pruned_bitcoind() -> Node {
    let mut conf = Conf::default();
    conf.args.extend(["-prune=1", "-fastprune"]);
    Node::with_conf("bitcoind", &conf).expect("pruned bitcoind must start")
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
) -> OperatorWallet<MemoryStore> {
    let config = OperatorWalletConfig::new(Amount::from_sat(330), 0, Network::Regtest)
        .with_persist_every_blocks(persist_every_blocks);
    open_wallet_with_config(
        bitcoind,
        general_seed,
        reserved_seed,
        stores,
        bootstrap_checkpoint,
        config,
    )
    .await
}

/// [`open_wallet`] with the whole config under the test's control.
async fn open_wallet_with_config(
    bitcoind: &Node,
    general_seed: u8,
    reserved_seed: u8,
    stores: &Stores,
    bootstrap_checkpoint: Option<BlockId>,
    config: OperatorWalletConfig,
) -> OperatorWallet<MemoryStore> {
    let (_, general_pubkey) = keypair_from_seed(general_seed);
    let (_, reserved_pubkey) = keypair_from_seed(reserved_seed);

    OperatorWallet::load_or_create(
        GeneralCustody::SecretService {
            general_key: general_pubkey,
            store: stores.general.clone(),
        },
        reserved_pubkey,
        config,
        Backend::BitcoinCore(Arc::new(sync_rpc_client(bitcoind))),
        stores.reserved.clone(),
        bootstrap_checkpoint,
        BTreeSet::new(),
    )
    .await
    .expect("wallet init")
}

/// Builds a fully-wired [`OperatorWallet`] against fresh in-memory stores. Funds the general wallet
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
    OperatorWallet<MemoryStore>,
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
/// the descriptor-only wallet returns unsigned. Returns the extracted
/// signed transaction.
fn sign_and_finalize(psbt: Psbt, keypair: Keypair) -> Transaction {
    let keys = vec![keypair; psbt.inputs.len()];
    sign_and_finalize_with(psbt, &keys)
}

/// [`sign_and_finalize`] with one keypair per input, in input order.
fn sign_and_finalize_with(mut psbt: Psbt, keys: &[Keypair]) -> Transaction {
    assert_eq!(keys.len(), psbt.inputs.len(), "one key per input");
    let secp = Secp256k1::new();
    let prevouts: Vec<_> = psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().expect("witness_utxo on every input"))
        .collect();
    let unsigned = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned);
    for (i, keypair) in keys.iter().enumerate() {
        let tweaked = keypair.tap_tweak(&secp, None).to_keypair();
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

/// The payout descriptor and the wallet's own receive script must be the SAME script:
/// payouts then arrive as ordinary wallet UTXOs (BDK tracks them) and are spent — including
/// CPFP force-spends of the unconfirmed payout — with the same tap-tweaking signer as any
/// funding input. A payout descriptor keyed to anything the funding descriptor doesn't
/// watch (e.g. the raw, untweaked general key, which BOSD would use verbatim as the output
/// key) silently strands every payout: invisible to the wallet and unspendable by the
/// production signers.
#[tokio::test]
#[serial]
async fn payout_descriptor_is_the_wallet_receive_script() {
    let bitcoind = setup_bitcoind();
    let (wallet, _kp, _pk) =
        build_operator_wallet(&bitcoind, 1, 2, 1, Amount::from_btc(0.5).unwrap()).await;

    assert_eq!(
        wallet.descriptor().expect("descriptor").to_script(),
        wallet.general().script_pubkey(),
        "secret-service payout descriptor must resolve to the funding wallet's own script"
    );
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
            GeneralUtxoPolicy::ConfirmedOnly,
            LeaseOwner::ClaimFundingRefill,
        )
        .expect("funding must succeed");

    // The returned lease must hold every funding input, so that a concurrent duty cannot
    // select one of them.
    let leased = wallet.leased_outpoints();
    assert!(!leased.is_empty(), "the lease must hold the funding inputs");
    for spent in funded.lease().outpoints() {
        assert!(
            leased.contains(spent),
            "every spent outpoint must be held; missing {spent}"
        );
    }

    // The PSBT must carry the requested quantity of reserved-wallet outputs.
    let reserved_script = wallet.reserved_script_pubkey();
    let (psbt, _funding_lease) = funded.into_parts();
    let reserved_output_count = psbt
        .unsigned_tx
        .output
        .iter()
        .filter(|o| o.value == utxo_value && o.script_pubkey == reserved_script)
        .count();
    assert_eq!(
        reserved_output_count, quantity,
        "PSBT must contain {quantity} reserved-wallet outputs of {utxo_value}"
    );

    // Sign, broadcast, confirm, and resync. The reserved pool then holds the new UTXOs.
    let signed = sign_and_finalize(psbt, general_kp);
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
async fn a_named_input_outside_the_general_wallet_is_an_unknown_input() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, _, _) = build_operator_wallet(&bitcoind, 13, 14, 0, Amount::ZERO).await;

    let unknown = OutPoint::new(Txid::from_byte_array([7; 32]), 0);
    let output = TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: wallet.reserved_script_pubkey(),
    };
    let err = wallet
        .fund_v3_transaction_with_inputs(
            vec![output],
            &[unknown],
            FeeRate::from_sat_per_vb(5).unwrap(),
            LeaseOwner::StakeFunding,
        )
        .expect_err("the wallet does not hold this input");
    assert!(
        matches!(err, OperatorWalletError::UnknownInput(outpoint) if outpoint == unknown),
        "got {err:?}"
    );
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
            LeaseOwner::ClaimFundingRefill,
        )
        .expect_err("unconfirmed general-wallet funds must not be selected");

    assert!(
        matches!(
            err,
            OperatorWalletError::NoConfirmedGeneralUtxos {
                unconfirmed_count: 1,
                unconfirmed_amount: amount,
            } if amount == unconfirmed_amount
        ),
        "expected the unconfirmed-only error, got {err:?}"
    );
    assert!(
        wallet.leased_outpoints().is_empty(),
        "failed refill must not lease the unconfirmed UTXO"
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
            LeaseOwner::ClaimFundingRefill,
        )
        .expect("confirmed funds should fund reserved UTXOs");

    assert!(
        funded.lease().outpoints().contains(&confirmed_outpoint),
        "funding transaction should spend the confirmed UTXO"
    );
    assert!(
        !funded.lease().outpoints().contains(&unconfirmed_outpoint),
        "funding transaction must exclude the unconfirmed UTXO"
    );
}

#[tokio::test]
#[serial]
async fn reserve_settled_picks_and_leases_one() {
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
            GeneralUtxoPolicy::ConfirmedOnly,
            LeaseOwner::ClaimFundingRefill,
        )
        .expect("seed funding");
    let (seed_psbt, seed_lease) = funded.into_parts();
    let signed = sign_and_finalize(seed_psbt, general_kp);
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

    // Clear the lease state. The seed transaction's inputs are held by its lease, and the
    // sync above already pruned them because the spend confirmed. The new reserved UTXOs are
    // free. This test covers `reserve_settled` against that pool.
    drop(seed_lease);
    assert!(wallet.leased_outpoints().is_empty(), "lease state cleared");

    let (picked, picked_lease) = wallet
        .reserve_settled(utxo_value, 0)
        .expect("must return one outpoint");
    assert!(
        wallet.leased_outpoints().contains(&picked),
        "picked outpoint must be held"
    );

    // A second pick skips the held outpoint and returns a different one.
    let (picked_again, _picked_again_lease) = wallet
        .reserve_settled(utxo_value, 0)
        .expect("must return another outpoint");
    assert_ne!(picked_again, picked, "must pick a different free UTXO");

    // Dropping the first lease returns its outpoint to the pool.
    drop(picked_lease);
    assert!(
        !wallet.leased_outpoints().contains(&picked),
        "a dropped lease must return its outpoint to the pool"
    );
}

#[tokio::test]
#[serial]
async fn reserved_pool_lookup_filters_by_value() {
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
                GeneralUtxoPolicy::ConfirmedOnly,
                LeaseOwner::ClaimFundingRefill,
            )
            .unwrap_or_else(|e| panic!("seed funding for {value} failed: {e}"));
        let (psbt, _lease) = funded.into_parts();
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
async fn settled_accepts_unconfirmed_outputs_only_from_own_refills() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, general_kp, _) =
        build_operator_wallet(&bitcoind, 19, 20, 2, Amount::from_btc(0.5).unwrap()).await;
    let utxo_value = Amount::from_btc(0.01).unwrap();
    let bury_depth = 2;

    let miner_addr = bitcoind.client.new_address().expect("miner");
    bitcoind
        .client
        .generate_to_address(bury_depth as usize, &miner_addr)
        .expect("bury inputs");
    wallet.sync().await.expect("sync buried inputs");

    // Two pool-sized outputs, both unconfirmed: one paid in by bitcoind's wallet, one from our
    // own refill.
    let reserved_address = Address::from_script(&wallet.reserved_script_pubkey(), Network::Regtest)
        .expect("reserved address");
    bitcoind
        .client
        .send_to_address(&reserved_address, utxo_value)
        .expect("send external output");
    let funded = wallet
        .create_reserved_utxos(
            FeeRate::from_sat_per_vb(5).unwrap(),
            utxo_value,
            1,
            GeneralUtxoPolicy::BuriedOnly { bury_depth },
            LeaseOwner::ClaimFundingRefill,
        )
        .expect("refill");
    let (psbt, _refill_lease) = funded.into_parts();
    let refill_txid = psbt.unsigned_tx.compute_txid();
    let signed = sign_and_finalize(psbt, general_kp);
    bitcoind
        .client
        .send_raw_transaction(&signed)
        .expect("broadcast refill");
    wallet.sync().await.expect("sync mempool");

    // The txids of the outputs that are settled at `depth`. The leases drop on return, so each
    // call sees the whole pool.
    let settled = |wallet: &mut OperatorWallet<MemoryStore>, depth: u32| -> Vec<Txid> {
        std::iter::from_fn(|| wallet.reserve_settled(utxo_value, depth))
            .collect::<Vec<_>>()
            .into_iter()
            .map(|(outpoint, _lease)| outpoint.txid)
            .collect()
    };

    assert_eq!(
        wallet.reserved_utxos_with_value(utxo_value).len(),
        2,
        "both unconfirmed outputs are in the pool"
    );
    assert_eq!(
        settled(&mut wallet, bury_depth),
        vec![refill_txid],
        "only the refill output is settled while unconfirmed"
    );
    assert!(
        settled(&mut wallet, bury_depth + 1).is_empty(),
        "refill trust must not exceed its input burial policy"
    );
    assert_eq!(
        settled(&mut wallet, 0),
        vec![refill_txid],
        "depth zero must still reject external mempool outputs"
    );

    // Confirmations include the transaction's own block, so burial needs one more.
    bitcoind
        .client
        .generate_to_address(bury_depth as usize, &miner_addr)
        .expect("mine");
    wallet.sync().await.expect("sync confirmations");
    assert_eq!(
        settled(&mut wallet, bury_depth),
        vec![refill_txid],
        "external outputs at exactly bury_depth confirmations are not buried"
    );
    assert_eq!(
        settled(&mut wallet, 0).len(),
        2,
        "depth zero accepts mined outputs"
    );

    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine burial block");
    wallet.sync().await.expect("sync burial");
    assert_eq!(
        settled(&mut wallet, bury_depth).len(),
        2,
        "buried outputs are settled regardless of origin"
    );
}

#[tokio::test]
#[serial]
async fn refill_requires_buried_inputs() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, _, _) =
        build_operator_wallet(&bitcoind, 21, 22, 1, Amount::from_btc(0.5).unwrap()).await;
    let bury_depth = 2;
    let miner_addr = bitcoind.client.new_address().expect("miner");
    let value = Amount::from_btc(0.01).unwrap();
    let policy = GeneralUtxoPolicy::BuriedOnly { bury_depth };
    let fee_rate = FeeRate::from_sat_per_vb(5).unwrap();

    for confirmations in 1..=bury_depth {
        wallet.sync().await.expect("sync input confirmations");
        assert_eq!(
            wallet.general().list_utxos()[0].confirmations,
            confirmations,
            "the general output has the expected depth"
        );
        let err = wallet
            .create_reserved_utxos(fee_rate, value, 1, policy, LeaseOwner::ClaimFundingRefill)
            .expect_err("shallow inputs must be rejected");
        assert!(
            matches!(
                err,
                OperatorWalletError::NoBuriedGeneralUtxos { bury_depth: 2 }
            ),
            "an input below the bury depth is refused"
        );
        assert!(
            wallet.leased_outpoints().is_empty(),
            "a refused refill takes no lease"
        );
        bitcoind
            .client
            .generate_to_address(1, &miner_addr)
            .expect("mine");
    }

    wallet.sync().await.expect("sync buried input");
    let funded = wallet
        .create_reserved_utxos(fee_rate, value, 1, policy, LeaseOwner::ClaimFundingRefill)
        .expect("buried input must be accepted");
    assert_eq!(
        funded.lease().outpoints().len(),
        1,
        "a buried input funds the refill under one lease"
    );
}

/// Durable storage holds the outpoints of stored reservations across a restart. A restarted wallet
/// must hold them from its first selection, and a confirmed spend must end only the spent one.
#[tokio::test]
#[serial]
async fn initial_leases_hold_outpoints_across_a_restart() {
    let bitcoind = setup_bitcoind();
    let stores = Stores::default();
    let (general_kp, general_pubkey) = keypair_from_seed(75);
    let (_, reserved_pubkey) = keypair_from_seed(76);
    let mut wallet = open_wallet(
        &bitcoind,
        75,
        76,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    let general_script = wallet.general().script_pubkey();
    let general_address =
        Address::from_script(&general_script, Network::Regtest).expect("general address");
    for _ in 0..2 {
        bitcoind
            .client
            .send_to_address(&general_address, Amount::from_btc(0.5).unwrap())
            .expect("send_to_address");
    }
    let miner_addr = bitcoind.client.new_address().expect("miner");
    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine");
    wallet.sync().await.expect("sync before the restart");
    let utxos = wallet.general().list_utxos();
    let (spent, live) = (utxos[0].clone(), utxos[1].outpoint);
    drop(wallet);

    let mut wallet = OperatorWallet::load_or_create(
        GeneralCustody::SecretService {
            general_key: general_pubkey,
            store: stores.general.clone(),
        },
        reserved_pubkey,
        OperatorWalletConfig::new(Amount::from_sat(330), 0, Network::Regtest),
        Backend::BitcoinCore(Arc::new(sync_rpc_client(&bitcoind))),
        stores.reserved.clone(),
        None,
        BTreeSet::from([spent.outpoint, live]),
    )
    .await
    .expect("wallet reopens");
    wallet.sync().await.expect("sync after the restart");

    assert_eq!(
        wallet.leased_outpoints(),
        BTreeSet::from([spent.outpoint, live]),
        "the restarted wallet holds both stored outpoints"
    );
    assert_eq!(wallet.general().list_utxos().len(), 2, "both outputs exist");
    assert!(
        wallet
            .select_general_utxo(LeaseOwner::StakeFunding, Amount::ONE_SAT)
            .is_none(),
        "selection must not offer an outpoint that a stored reservation holds"
    );

    let unsigned_tx = Transaction {
        version: bdk_wallet::bitcoin::transaction::Version(3),
        lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
        input: vec![bdk_wallet::bitcoin::TxIn {
            previous_output: spent.outpoint,
            ..Default::default()
        }],
        output: vec![TxOut {
            value: spent.amount - Amount::from_sat(2_000),
            script_pubkey: general_script,
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx).expect("from_unsigned_tx");
    psbt.inputs[0].witness_utxo = Some(TxOut::from(&spent));
    bitcoind
        .client
        .send_raw_transaction(&sign_and_finalize(psbt, general_kp))
        .expect("broadcast");
    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine");
    wallet.sync().await.expect("sync after the spend");

    assert_eq!(
        wallet.leased_outpoints(),
        BTreeSet::from([live]),
        "a confirmed spend ends its lease and leaves the other in place"
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
            GeneralUtxoPolicy::ConfirmedOnly,
            LeaseOwner::ClaimFundingRefill,
        )
        .expect("first seed");
    let (first_psbt, _first_lease) = first.into_parts();
    let signed = sign_and_finalize(first_psbt, general_kp);
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
            GeneralUtxoPolicy::ConfirmedOnly,
            LeaseOwner::ClaimFundingRefill,
        )
        .expect("refill");
    for spent in refill.lease().outpoints() {
        assert!(
            !pool_outpoints_first.contains(spent),
            "refill must not spend an existing pool UTXO ({spent})"
        );
    }
    let (refill_psbt, _refill_lease) = refill.into_parts();
    let signed_refill = sign_and_finalize(refill_psbt, general_kp);
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

/// Mines one block holding its coinbase and `txs`, taking nothing from the mempool.
fn mine_block_with(bitcoind: &Node, txs: &[&Transaction]) {
    let addr = bitcoind.client.new_address().expect("miner address");
    let txs = txs
        .iter()
        .map(|tx| Value::String(serialize_hex(*tx)))
        .collect();
    bitcoind
        .client
        .call::<Value>(
            "generateblock",
            &[Value::String(addr.to_string()), Value::Array(txs)],
        )
        .expect("mine a block");
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
    assert!(
        wallet.general().list_utxos().is_empty(),
        "nothing is spendable before the first sync of this process"
    );

    wallet.sync().await.expect("post-restart sync");
    let utxos_after_sync: BTreeSet<OutPoint> = wallet
        .general()
        .list_utxos()
        .into_iter()
        .map(|u| u.outpoint)
        .collect();
    assert_eq!(
        utxos_after_sync, utxos_before,
        "transaction-graph state survives the restart"
    );
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
    let mut wallet = wallet;
    wallet.sync().await.expect("sync after the reopen");
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
    let mut wallet = open_wallet(
        &bitcoind,
        35,
        36,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    wallet.sync().await.expect("sync after the restart");
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
    let (_, reserved_pubkey) = keypair_from_seed(40);
    let err = OperatorWallet::load_or_create(
        GeneralCustody::SecretService {
            general_key: general_pubkey,
            store: stores.general.clone(),
        },
        reserved_pubkey,
        OperatorWalletConfig::new(Amount::from_sat(330), 0, Network::Regtest),
        Backend::BitcoinCore(Arc::new(sync_rpc_client(&bitcoind))),
        stores.reserved.clone(),
        None,
        BTreeSet::new(),
    )
    .await
    .expect_err("a store ahead of the node must be refused");
    let OperatorWalletError::GeneralInit(err) = err else {
        panic!("got {err:?}");
    };
    assert!(
        matches!(
            err.downcast_ref::<InitError<MemoryStoreError>>(),
            Some(InitError::BackendBehindTip { tip: stored, .. }) if *stored == tip
        ),
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
    let leased = wallet.reserved_utxos_with_value(value)[0].outpoint;
    wallet.lease_committed(vec![leased], LeaseOwner::ClaimFunding);

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

/// Callers carry on after a failed sync, so a failed sync leaves the spendable set as the last
/// successful one saw it. Unconfirmed outputs depend on this: they are spendable only through the
/// mempool snapshot.
#[tokio::test]
#[serial]
async fn unconfirmed_outputs_stay_spendable_across_a_failed_sync() {
    let bitcoind = setup_bitcoind();
    let stores = Stores::default();
    let (general_kp, general_pubkey) = keypair_from_seed(45);
    // No retries: the injected failure fires once, and a retry would succeed.
    let config = OperatorWalletConfig::new(Amount::from_sat(330), 0, Network::Regtest)
        .with_sync_policy(0, 1, Duration::ZERO);
    let mut wallet = open_wallet_with_config(&bitcoind, 45, 46, &stores, None, config).await;

    let general_addr = Address::p2tr(&Secp256k1::new(), general_pubkey, None, Network::Regtest);
    bitcoind
        .client
        .send_to_address(&general_addr, Amount::from_btc(0.5).unwrap())
        .expect("fund the general wallet");
    mine(&bitcoind, 1);
    wallet.sync().await.expect("initial sync");

    // Fund the pool and leave the funding transaction in the mempool.
    let value = Amount::from_btc(0.01).unwrap();
    let quantity = 3;
    let funded = wallet
        .create_reserved_utxos(
            FeeRate::from_sat_per_vb(5).unwrap(),
            value,
            quantity,
            GeneralUtxoPolicy::ConfirmedOnly,
            LeaseOwner::ClaimFundingRefill,
        )
        .expect("fund the pool");
    let (psbt, _funding_lease) = funded.into_parts();
    let signed = sign_and_finalize(psbt, general_kp);
    bitcoind
        .client
        .send_raw_transaction(&signed)
        .expect("broadcast");
    wallet
        .sync()
        .await
        .expect("sync with the funding in the mempool");
    let unconfirmed_general = |wallet: &OperatorWallet<MemoryStore>| {
        wallet
            .general()
            .list_utxos()
            .into_iter()
            .filter(|u| u.confirmations == 0)
            .count()
    };
    assert_eq!(wallet.reserved_utxos_with_value(value).len(), quantity);
    assert_eq!(
        unconfirmed_general(&wallet),
        1,
        "the change output is unconfirmed"
    );

    assert!(
        wallet.last_sync().is_some_and(|last| last.succeeded),
        "the last sync attempt succeeded"
    );

    // Fail the next commit of each store. An empty block gives both wallets something to commit
    // while the funding transaction stays unconfirmed.
    stores
        .general
        .fail_on_persist_call(stores.general.persist_calls() + 1);
    stores
        .reserved
        .fail_on_persist_call(stores.reserved.persist_calls() + 1);
    mine_block_with(&bitcoind, &[]);
    wallet.sync().await.expect_err("injected persist failure");
    assert!(
        wallet.last_sync().is_some_and(|last| !last.succeeded),
        "the last sync attempt records the failure"
    );

    // Both wallets still show what the last successful sync saw.
    assert_eq!(
        wallet.reserved_utxos_with_value(value).len(),
        quantity,
        "pool members still spendable"
    );
    assert_eq!(
        unconfirmed_general(&wallet),
        1,
        "general change still spendable"
    );

    // A clean attempt refreshes the snapshot; the funding is still in the mempool.
    wallet.sync().await.expect("retry");
    assert_eq!(wallet.reserved_utxos_with_value(value).len(), quantity);
    assert_eq!(unconfirmed_general(&wallet), 1);
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

/// A spend reorged out behind a conflict the wallet never sees is on neither the chain nor the
/// mempool. BDK keeps it canonical in memory, and its inputs are spendable all the same.
#[tokio::test]
#[serial]
async fn inputs_of_a_reorged_out_spend_are_spendable() {
    let bitcoind = setup_bitcoind();
    let rpc = sync_rpc_client(&bitcoind);
    let stores = Stores::default();
    let (general_kp, general_pubkey) = keypair_from_seed(47);
    let mut wallet = open_wallet(
        &bitcoind,
        47,
        48,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;

    // One coin in the general wallet and one under an unrelated key, confirmed together.
    let secp = Secp256k1::new();
    let general_addr = Address::p2tr(&secp, general_pubkey, None, Network::Regtest);
    let (other_kp, other_pubkey) = keypair_from_seed(49);
    let other_addr = Address::p2tr(&secp, other_pubkey, None, Network::Regtest);
    let value = Amount::from_btc(0.5).unwrap();
    rpc.send_to_address(&general_addr, value, None, None, None, None, None, None)
        .expect("fund the general wallet");
    let other_txid = rpc
        .send_to_address(&other_addr, value, None, None, None, None, None, None)
        .expect("fund the other key");
    mine(&bitcoind, 1);
    wallet.sync().await.expect("sync");
    let coin = wallet
        .general()
        .list_utxos()
        .pop()
        .expect("the general coin");
    let other_tx = rpc
        .get_raw_transaction(&other_txid, None)
        .expect("other funding tx");
    let other_vout = other_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == other_addr.script_pubkey())
        .expect("output to the other key");
    let other = OutPoint {
        txid: other_txid,
        vout: other_vout as u32,
    };
    let other_txout = other_tx.output[other_vout].clone();

    // A spend of both coins, confirmed.
    let sink = bitcoind
        .client
        .new_address()
        .expect("sink address")
        .script_pubkey();
    let fee = Amount::from_sat(2_000);
    let input = |outpoint| TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };
    let spend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input(coin.outpoint), input(other)],
        output: vec![TxOut {
            value: coin.amount + other_txout.value - fee,
            script_pubkey: sink.clone(),
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(spend).expect("psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut::from(&coin));
    psbt.inputs[1].witness_utxo = Some(other_txout.clone());
    let spend = sign_and_finalize_with(psbt, &[general_kp, other_kp]);
    let spend_txid = rpc
        .send_raw_transaction(&spend)
        .expect("broadcast the spend");
    mine(&bitcoind, 1);
    wallet.sync().await.expect("sync with the spend confirmed");
    assert!(
        wallet.general().list_utxos().is_empty(),
        "the coin is spent"
    );

    // Reorg the spend out behind a block spending the other coin elsewhere: the spend is invalid
    // there, so the node drops it, and the conflict touches no wallet script.
    let height = rpc.get_block_count().expect("height");
    rpc.invalidate_block(&rpc.get_block_hash(height).expect("block hash"))
        .expect("invalidate");
    let conflict = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![input(other)],
        output: vec![TxOut {
            value: other_txout.value - fee,
            script_pubkey: sink,
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(conflict).expect("psbt");
    psbt.inputs[0].witness_utxo = Some(other_txout);
    let conflict = sign_and_finalize_with(psbt, &[other_kp]);
    mine_block_with(&bitcoind, &[&conflict]);
    assert!(
        rpc.get_mempool_entry(&spend_txid).is_err(),
        "the spend is gone from the mempool"
    );
    wallet.sync().await.expect("sync after the reorg");
    let outpoints = |wallet: &OperatorWallet<MemoryStore>| -> Vec<OutPoint> {
        wallet
            .general()
            .list_utxos()
            .into_iter()
            .map(|u| u.outpoint)
            .collect()
    };
    assert_eq!(outpoints(&wallet), vec![coin.outpoint], "the coin is back");

    // The spend stays in the graph after a load, so the coin stays hidden until a sync finishes.
    drop(wallet);
    let mut wallet = open_wallet(
        &bitcoind,
        47,
        48,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    assert!(outpoints(&wallet).is_empty(), "no sync has finished");
    wallet.sync().await.expect("sync after the restart");
    assert_eq!(outpoints(&wallet), vec![coin.outpoint], "and stays back");
}

/// One coin in the general wallet of `seed`, confirmed once, with the keypair that signs for it.
async fn wallet_with_one_buried_coin(
    bitcoind: &Node,
    stores: &Stores,
    seed: u8,
    bury_depth: u32,
) -> (
    OperatorWallet<MemoryStore>,
    Keypair,
    operator_wallet::UtxoInfo,
) {
    let (general_kp, general_pubkey) = keypair_from_seed(seed);
    let config = OperatorWalletConfig::new(Amount::from_sat(330), bury_depth, Network::Regtest);
    let mut wallet = open_wallet_with_config(bitcoind, seed, seed + 1, stores, None, config).await;
    let general_addr = Address::p2tr(&Secp256k1::new(), general_pubkey, None, Network::Regtest);
    bitcoind
        .client
        .send_to_address(&general_addr, Amount::from_btc(0.5).unwrap())
        .expect("fund the general wallet");
    mine(bitcoind, 1);
    wallet.sync().await.expect("sync");
    let coin = wallet
        .general()
        .list_utxos()
        .pop()
        .expect("the general coin");
    (wallet, general_kp, coin)
}

/// A signed spend of `coin` to `sink`, plus `extra` inputs signed with `extra_keys`.
fn spend_of(
    coin: &operator_wallet::UtxoInfo,
    coin_key: &Keypair,
    extra: &[(OutPoint, TxOut, Keypair)],
    sink: ScriptBuf,
) -> Transaction {
    let fee = Amount::from_sat(2_000);
    let input = |outpoint| TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    };
    let total = coin.amount
        + extra
            .iter()
            .map(|(_, txout, _)| txout.value)
            .sum::<Amount>();
    let spend = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: std::iter::once(input(coin.outpoint))
            .chain(extra.iter().map(|(outpoint, _, _)| input(*outpoint)))
            .collect(),
        output: vec![TxOut {
            value: total - fee,
            script_pubkey: sink,
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(spend).expect("psbt");
    psbt.inputs[0].witness_utxo = Some(TxOut::from(coin));
    for (i, (_, txout, _)) in extra.iter().enumerate() {
        psbt.inputs[i + 1].witness_utxo = Some(txout.clone());
    }
    let keys: Vec<Keypair> = std::iter::once(*coin_key)
        .chain(extra.iter().map(|(_, _, key)| *key))
        .collect();
    sign_and_finalize_with(psbt, &keys)
}

/// A committed lease outlives the confirmation of its spend. The sync drops it only once the
/// spend has more than `bury_depth` confirmations, so a reorg inside the depth cannot free an
/// outpoint that a durable row still names.
#[tokio::test]
#[serial]
async fn a_lease_holds_until_its_spend_is_buried() {
    let bitcoind = setup_bitcoind();
    let stores = Stores::default();
    let bury_depth = 2;
    let (mut wallet, general_kp, coin) =
        wallet_with_one_buried_coin(&bitcoind, &stores, 61, bury_depth).await;
    wallet.lease_committed(vec![coin.outpoint], LeaseOwner::WithdrawalFulfillment);

    let sink = bitcoind.client.new_address().expect("sink").script_pubkey();
    let spend = spend_of(&coin, &general_kp, &[], sink);
    bitcoind
        .client
        .send_raw_transaction(&spend)
        .expect("broadcast the spend");
    wallet
        .sync()
        .await
        .expect("sync with the spend in the mempool");
    assert!(
        wallet.leased_outpoints().contains(&coin.outpoint),
        "a mempool spend keeps the lease"
    );

    for confirmations in 1..=bury_depth {
        mine(&bitcoind, 1);
        wallet.sync().await.expect("sync");
        assert!(
            wallet.leased_outpoints().contains(&coin.outpoint),
            "{confirmations} confirmations keep the lease"
        );
    }
    mine(&bitcoind, 1);
    wallet.sync().await.expect("sync at burial");
    assert!(
        wallet.leased_outpoints().is_empty(),
        "a buried spend drops the lease"
    );
}

/// A reorg that removes a once-confirmed spend returns its input to the wallet. The lease is still
/// there, so no duty can select the input while a durable row names it.
#[tokio::test]
#[serial]
async fn a_lease_survives_a_reorg_of_its_confirmed_spend() {
    let bitcoind = setup_bitcoind();
    let rpc = sync_rpc_client(&bitcoind);
    let stores = Stores::default();
    let (mut wallet, general_kp, coin) =
        wallet_with_one_buried_coin(&bitcoind, &stores, 63, 2).await;
    wallet.lease_committed(vec![coin.outpoint], LeaseOwner::WithdrawalFulfillment);

    // A coin under an unrelated key gives the reorg a conflict that touches no wallet script.
    let (other_kp, other_pubkey) = keypair_from_seed(65);
    let other_addr = Address::p2tr(&Secp256k1::new(), other_pubkey, None, Network::Regtest);
    let other_txid = rpc
        .send_to_address(
            &other_addr,
            Amount::from_btc(0.5).unwrap(),
            None,
            None,
            None,
            None,
            None,
            None,
        )
        .expect("fund the other key");
    mine(&bitcoind, 1);
    let other_tx = rpc
        .get_raw_transaction(&other_txid, None)
        .expect("other funding tx");
    let other_vout = other_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == other_addr.script_pubkey())
        .expect("output to the other key");
    let other = OutPoint {
        txid: other_txid,
        vout: other_vout as u32,
    };
    let other_txout = other_tx.output[other_vout].clone();

    let sink = bitcoind.client.new_address().expect("sink").script_pubkey();
    let spend = spend_of(
        &coin,
        &general_kp,
        &[(other, other_txout.clone(), other_kp)],
        sink.clone(),
    );
    let spend_txid = rpc
        .send_raw_transaction(&spend)
        .expect("broadcast the spend");
    mine(&bitcoind, 1);
    wallet.sync().await.expect("sync with the spend confirmed");
    assert!(
        wallet.general().list_utxos().is_empty(),
        "the coin is spent"
    );
    assert!(
        wallet.leased_outpoints().contains(&coin.outpoint),
        "a confirmed spend below the bury depth keeps the lease"
    );

    // Reorg the spend out behind a block that spends the other coin elsewhere.
    let height = rpc.get_block_count().expect("height");
    rpc.invalidate_block(&rpc.get_block_hash(height).expect("block hash"))
        .expect("invalidate");
    let conflict = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: other,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: other_txout.value - Amount::from_sat(2_000),
            script_pubkey: sink,
        }],
    };
    let mut psbt = Psbt::from_unsigned_tx(conflict).expect("psbt");
    psbt.inputs[0].witness_utxo = Some(other_txout);
    let conflict = sign_and_finalize_with(psbt, &[other_kp]);
    mine_block_with(&bitcoind, &[&conflict]);
    assert!(
        rpc.get_mempool_entry(&spend_txid).is_err(),
        "the spend is gone from the mempool"
    );
    wallet.sync().await.expect("sync after the reorg");

    let listed: Vec<OutPoint> = wallet
        .general()
        .list_utxos()
        .into_iter()
        .map(|u| u.outpoint)
        .collect();
    assert_eq!(
        listed,
        vec![coin.outpoint],
        "the coin is back in the wallet"
    );
    assert!(
        wallet.leased_outpoints().contains(&coin.outpoint),
        "and its lease still holds"
    );
    assert!(
        wallet
            .select_general_utxo(LeaseOwner::BridgeProof, Amount::ONE_SAT)
            .is_none(),
        "no duty can select a held coin"
    );
}

/// A funding path that stores its inputs in a durable row selects only buried inputs, so a reorg
/// no deeper than `bury_depth` cannot remove an input the row names.
#[tokio::test]
#[serial]
async fn row_backed_funding_selects_only_buried_inputs() {
    let bitcoind = setup_bitcoind();
    let stores = Stores::default();
    let bury_depth = 2;
    let (mut wallet, _, _) = wallet_with_one_buried_coin(&bitcoind, &stores, 67, bury_depth).await;
    let sink = bitcoind.client.new_address().expect("sink").script_pubkey();
    let outputs = vec![TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: sink,
    }];
    let fee_rate = FeeRate::from_sat_per_vb(2).unwrap();

    for confirmations in 1..=bury_depth {
        assert!(
            matches!(
                wallet.fund_v3_transaction(
                    outputs.clone(),
                    fee_rate,
                    GeneralUtxoPolicy::BuriedOnly { bury_depth },
                    LeaseOwner::WithdrawalFulfillment,
                ),
                Err(OperatorWalletError::NoBuriedGeneralUtxos { bury_depth: 2 })
            ),
            "{confirmations} confirmations do not fund a row"
        );
        mine(&bitcoind, 1);
        wallet.sync().await.expect("sync");
    }
    let funded = wallet
        .fund_v3_transaction(
            outputs,
            fee_rate,
            GeneralUtxoPolicy::BuriedOnly { bury_depth },
            LeaseOwner::WithdrawalFulfillment,
        )
        .expect("a buried coin funds the row");
    assert_eq!(
        funded.lease().outpoints().len(),
        1,
        "a buried input funds the row-backed transaction under one lease"
    );
}

/// `IncludeUnconfirmed` admits a mempool credit.
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
            LeaseOwner::StakeFunding,
        )
        .expect("unconfirmed general-wallet funds may be selected when allowed");

    assert!(
        funded.lease().outpoints().contains(&unconfirmed_outpoint),
        "funding transaction should spend the unconfirmed general-wallet UTXO"
    );
    assert!(
        wallet.leased_outpoints().contains(&unconfirmed_outpoint),
        "selected unconfirmed UTXO must be leased"
    );
}

/// `reserved_utxo` finds a pool member of any denomination by its outpoint, and nothing else.
#[tokio::test]
#[serial]
async fn reserved_utxo_finds_an_outpoint_of_any_value() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, general_kp, _) =
        build_operator_wallet(&bitcoind, 7, 8, 3, Amount::from_btc(0.5).unwrap()).await;

    let values = [
        Amount::from_btc(0.01).unwrap(),
        Amount::from_btc(0.05).unwrap(),
    ];
    for value in values {
        let funded = wallet
            .create_reserved_utxos(
                FeeRate::from_sat_per_vb(5).unwrap(),
                value,
                1,
                GeneralUtxoPolicy::ConfirmedOnly,
                LeaseOwner::StakeFunding,
            )
            .unwrap_or_else(|e| panic!("seed funding for {value} failed: {e}"));
        let (psbt, lease) = funded.into_parts();
        lease.commit();
        let signed = sign_and_finalize(psbt, general_kp);
        bitcoind
            .client
            .send_raw_transaction(&signed)
            .expect("broadcast");
        mine(&bitcoind, 1);
        wallet.sync().await.expect("sync");
    }

    for value in values {
        let pooled = wallet.reserved_utxos_with_value(value);
        assert_eq!(pooled.len(), 1, "expected one UTXO of {value}");
        let found = wallet
            .reserved_utxo(pooled[0].outpoint)
            .unwrap_or_else(|| panic!("the {value} UTXO must be found by its outpoint"));
        assert_eq!(
            (found.outpoint, found.amount),
            (pooled[0].outpoint, value),
            "lookup by outpoint must return the {value} UTXO"
        );
    }
    let unknown = OutPoint::new(Txid::all_zeros(), 0);
    assert!(
        wallet.reserved_utxo(unknown).is_none(),
        "an outpoint the reserved wallet does not hold must not be found"
    );
}

/// A settled output is settled by chain data alone, so a reopened wallet gives the answer that the
/// running wallet gave.
#[tokio::test]
#[serial]
async fn settlement_does_not_change_across_a_restart() {
    let bitcoind = setup_bitcoind();
    let stores = Stores::default();
    let open = || {
        open_wallet(
            &bitcoind,
            56,
            57,
            &stores,
            None,
            DEFAULT_PERSIST_EVERY_BLOCKS,
        )
    };
    let mut wallet = open().await;
    let value = Amount::from_btc(0.02).unwrap();
    let reserved_address = Address::from_script(&wallet.reserved_script_pubkey(), Network::Regtest)
        .expect("reserved address");
    bitcoind
        .client
        .send_to_address(&reserved_address, value)
        .expect("pay the reserved script");
    mine(&bitcoind, 2);
    wallet.sync().await.expect("sync");
    assert!(wallet.reserve_settled(value, 2).is_none(), "not yet buried");
    assert!(wallet.reserve_settled(value, 1).is_some(), "buried at 1");

    drop(wallet);
    let mut wallet = open().await;
    wallet.sync().await.expect("sync after the restart");
    assert!(wallet.reserve_settled(value, 2).is_none(), "not yet buried");
    assert!(wallet.reserve_settled(value, 1).is_some(), "buried at 1");
}

/// An outpoint that no wallet knows can be the output of a parent that no block holds yet, or of
/// a transaction that a reorg removed and that can return. Its lease must not end at a sync.
#[tokio::test]
#[serial]
async fn a_sync_keeps_a_lease_on_an_outpoint_that_no_wallet_knows() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, _, _) =
        build_operator_wallet(&bitcoind, 54, 55, 1, Amount::from_btc(0.5).unwrap()).await;
    let unknown = OutPoint::new(Txid::all_zeros(), 7);
    wallet.lease_committed(vec![unknown], LeaseOwner::StakeFunding);
    wallet.sync().await.expect("sync");
    assert!(
        wallet.leased_outpoints().contains(&unknown),
        "a sync keeps a lease that no wallet output backs"
    );
}

/// One claim funding output must not go to two graphs. The output is leased and committed, a
/// spend enters the mempool, and a conflict on its other input evicts it. The output reads as
/// spendable, the lease keeps it from a second caller, and a confirmed spend ends the lease.
#[tokio::test]
#[serial]
async fn a_committed_lease_outlives_a_spend_that_leaves_the_mempool() {
    let bitcoind = setup_bitcoind();
    let rpc = sync_rpc_client(&bitcoind);
    let stores = Stores::default();
    let (reserved_kp, _) = keypair_from_seed(52);
    let mut wallet = open_wallet(
        &bitcoind,
        51,
        52,
        &stores,
        None,
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;

    // One coin on the reserved script and one under an unrelated key, confirmed together.
    let value = Amount::from_btc(0.02).unwrap();
    let reserved_address = Address::from_script(&wallet.reserved_script_pubkey(), Network::Regtest)
        .expect("reserved address");
    let (other_kp, other_pubkey) = keypair_from_seed(53);
    let other_address = Address::p2tr(&Secp256k1::new(), other_pubkey, None, Network::Regtest);
    rpc.send_to_address(&reserved_address, value, None, None, None, None, None, None)
        .expect("pay the reserved script");
    let other_txid = rpc
        .send_to_address(&other_address, value, None, None, None, None, None, None)
        .expect("pay the other key");
    mine(&bitcoind, 1);
    wallet.sync().await.expect("sync the payments");
    let (coin, lease) = wallet
        .reserve_settled(value, 0)
        .expect("one settled output");
    lease.commit();

    let other_tx = rpc
        .get_raw_transaction(&other_txid, None)
        .expect("other funding tx");
    let other_vout = other_tx
        .output
        .iter()
        .position(|output| output.script_pubkey == other_address.script_pubkey())
        .expect("output to the other key");
    let other = OutPoint::new(other_txid, other_vout as u32);
    let other_txout = other_tx.output[other_vout].clone();
    let coin_txout = TxOut {
        value,
        script_pubkey: wallet.reserved_script_pubkey(),
    };
    let sink = bitcoind
        .client
        .new_address()
        .expect("sink address")
        .script_pubkey();
    // Every spend pays the node's wallet, so none adds an output to the wallets under test.
    let spend_of = |inputs: &[(OutPoint, &TxOut)], fee: u64, keys: &[Keypair]| {
        let total: Amount = inputs.iter().map(|(_, txout)| txout.value).sum();
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: inputs
                .iter()
                .map(|(outpoint, _)| TxIn {
                    previous_output: *outpoint,
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
                .collect(),
            output: vec![TxOut {
                value: total - Amount::from_sat(fee),
                script_pubkey: sink.clone(),
            }],
        };
        let mut psbt = Psbt::from_unsigned_tx(tx).expect("psbt");
        for (psbt_input, (_, txout)) in psbt.inputs.iter_mut().zip(inputs) {
            psbt_input.witness_utxo = Some((*txout).clone());
        }
        sign_and_finalize_with(psbt, keys)
    };

    let spend = spend_of(
        &[(coin, &coin_txout), (other, &other_txout)],
        2_000,
        &[reserved_kp, other_kp],
    );
    rpc.send_raw_transaction(&spend).expect("broadcast");
    wallet.sync().await.expect("sync the spend");
    assert!(
        wallet.reserved_utxos_with_value(value).is_empty(),
        "an output a mempool transaction spends is not offered"
    );
    assert!(
        wallet.leased_outpoints().contains(&coin),
        "a spend in the mempool keeps the lease"
    );

    let conflict = spend_of(&[(other, &other_txout)], 20_000, &[other_kp]);
    rpc.send_raw_transaction(&conflict).expect("replace");
    wallet.sync().await.expect("sync the eviction");
    assert_eq!(
        wallet.reserved_utxos_with_value(value).len(),
        1,
        "the spend is dead, so the output is spendable"
    );
    assert!(
        wallet.reserve_settled(value, 0).is_none(),
        "and the lease keeps it from a second graph"
    );

    let confirmed = spend_of(&[(coin, &coin_txout)], 2_000, &[reserved_kp]);
    rpc.send_raw_transaction(&confirmed).expect("broadcast");
    mine(&bitcoind, 1);
    wallet.sync().await.expect("sync the confirmed spend");
    assert!(
        !wallet.leased_outpoints().contains(&coin),
        "a confirmed spend ends the lease"
    );
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

#[tokio::test]
#[serial]
async fn sync_fails_when_the_seed_block_is_pruned() {
    let bitcoind = setup_pruned_bitcoind();
    let rpc = sync_rpc_client(&bitcoind);
    // Core keeps the last 288 blocks and deletes whole files, so mine well past both limits.
    mine(&bitcoind, 700);
    let _: u64 = rpc.call("pruneblockchain", &[400.into()]).expect("prune");
    let prune_height = rpc
        .get_blockchain_info()
        .expect("blockchain info")
        .prune_height
        .expect("a pruned node reports its prune height") as u32;
    assert!(prune_height > 1, "nothing was pruned: {prune_height}");
    let seed = |height: u32| BlockId {
        height,
        hash: rpc.get_block_hash(height.into()).expect("block hash"),
    };

    // A store is seeded at the bootstrap block's parent and the emitter fetches that parent
    // first, so a bootstrap height equal to the prune height points the first fetch at a block
    // the node has deleted.
    let stores = Stores::default();
    let mut wallet = open_wallet(
        &bitcoind,
        31,
        32,
        &stores,
        Some(seed(prune_height - 1)),
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    let err = wallet.sync().await.expect_err("the seed block is pruned");
    assert!(format!("{err:?}").contains("pruned"), "{err:?}");
    assert_eq!(
        wallet.local_chain_tip_height(),
        prune_height - 1,
        "a failed sync leaves the chain at the seed"
    );

    // One block higher the seed itself is retained and the sync runs to the tip.
    let stores = Stores::default();
    let mut wallet = open_wallet(
        &bitcoind,
        33,
        34,
        &stores,
        Some(seed(prune_height)),
        DEFAULT_PERSIST_EVERY_BLOCKS,
    )
    .await;
    wallet
        .sync()
        .await
        .expect("sync from the lowest retained block");
    assert_eq!(wallet.local_chain_tip_height(), 700);
}

/// Opens (loads or creates) an [`OperatorWallet`] whose two stores live in `data_dir`.
async fn open_sqlite_wallet(
    bitcoind: &Node,
    general_seed: u8,
    reserved_seed: u8,
    data_dir: &Path,
) -> OperatorWallet<SqliteStore> {
    let (_, general_pubkey) = keypair_from_seed(general_seed);
    let (_, reserved_pubkey) = keypair_from_seed(reserved_seed);
    let general_store =
        SqliteStore::open_in_dir(data_dir, WalletKind::General).expect("open general");
    let reserved_store =
        SqliteStore::open_in_dir(data_dir, WalletKind::Reserved).expect("open reserved");
    OperatorWallet::load_or_create(
        GeneralCustody::SecretService {
            general_key: general_pubkey,
            store: general_store,
        },
        reserved_pubkey,
        OperatorWalletConfig::new(Amount::from_sat(330), 0, Network::Regtest),
        Backend::BitcoinCore(Arc::new(sync_rpc_client(bitcoind))),
        reserved_store,
        None,
        BTreeSet::new(),
    )
    .await
    .expect("wallet init")
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
    assert!(
        wallet.general().list_utxos().is_empty(),
        "nothing is spendable before the first sync of this process"
    );

    wallet.sync().await.expect("post-restart sync");
    assert_eq!(
        wallet.local_chain_tip_height(),
        tip_before + 5,
        "the restarted wallet syncs to the new tip"
    );
    let utxos_after_sync: BTreeSet<OutPoint> = wallet
        .general()
        .list_utxos()
        .into_iter()
        .map(|u| u.outpoint)
        .collect();
    assert_eq!(
        utxos_after_sync, utxos_before,
        "graph state reloaded from SQLite"
    );
}

/// A rebuild looks past the lease of its prior child, and past no other lease.
#[tokio::test]
#[serial]
async fn a_rebuild_reaches_the_inputs_of_its_prior_child_and_no_other_held_input() {
    let bitcoind = setup_bitcoind();
    let (mut wallet, _, _) =
        build_operator_wallet(&bitcoind, 61, 62, 1, Amount::from_btc(0.5).unwrap()).await;
    wallet.sync().await.expect("sync");

    let parent = Transaction {
        version: Version(3),
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::from_sat(330),
            script_pubkey: wallet.reserved_script_pubkey(),
        }],
    };
    let spend = ChildSpend::keyed_anchor(OutPoint::new(parent.compute_txid(), 0));
    let target = FeeRate::from_sat_per_vb(5).unwrap();
    let cap = FeeRate::from_sat_per_vb(1000).unwrap();

    let (first, inputs) = wallet
        .build_cpfp_child(
            &parent,
            Amount::ZERO,
            &spend,
            target,
            cap,
            ReplacedChild::default(),
        )
        .expect("the first child must build");
    let (first, lease) = first.into_parts();

    let unrelated = wallet.build_cpfp_child(
        &parent,
        Amount::ZERO,
        &spend,
        target,
        cap,
        ReplacedChild::default(),
    );
    assert!(
        matches!(
            unrelated,
            Err(OperatorWalletError::InsufficientFunds { .. })
        ),
        "a build with no prior child must not reach a held input, got {unrelated:?}"
    );

    let prior = [PriorChild {
        txid: first.unsigned_tx.compute_txid(),
        lease: &lease,
        inputs: &inputs,
    }];
    let (rebuilt, _) = wallet
        .build_cpfp_child(
            &parent,
            Amount::ZERO,
            &spend,
            target,
            cap,
            ReplacedChild {
                prior: &prior,
                incumbent: None,
            },
        )
        .expect("a rebuild must reach the input of its prior child");
    assert_eq!(
        rebuilt.lease().outpoints(),
        lease.outpoints(),
        "the rebuild holds the same inputs as its prior child"
    );
}
