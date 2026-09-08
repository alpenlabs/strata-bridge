#![allow(unused_crate_dependencies)]
//! End-to-end CPFP regression test against a real `bitcoind` (regtest, via `corepc-node`).
//!
//! Validates STR-3439 AC2: aggressive CPFP submitted as a `[parent, child]` v3 package is
//! accepted by `bitcoind`'s `submitpackage` RPC and the package confirms when a block is mined.
//!
//! ## TRUC requirement
//!
//! Per BIP-431, a v3 child can only spend from a v3 parent. `bitcoind`'s default
//! `send_to_address` produces a v2 transaction, which submitpackage rejects when paired with
//! the v3 CPFP child this crate produces. The test therefore builds the parent itself via
//! `OperatorWallet::fund_v3_transaction`, signs it with the known operator privkey, and uses
//! that signed v3 transaction as the parent for `perform_bump`.
//!
//! ## Signing in the test
//!
//! `NativeGeneralWallet` is descriptor-only: it returns unsigned PSBTs. Production code
//! signs those via secret-service; in this test we sign in-process using the operator's
//! known keypair (Taproot key-path with BIP-341 tap-tweak). The parent's funding input is
//! signed in `build_v3_parent` / `build_v3_payout_parent`; the child's inputs (anchor or
//! payout + wallet funding) are signed by `perform_bump` via the `InputSigner` closures in
//! `CpfpContext` (here just `test_input_signer`, which signs everything with the operator's
//! known keypair since both the anchor key and the wallet descriptor key are the same in
//! the test).
//!
//! Test is gated on `bitcoind` being available; it's a `#[serial]` test because `bitcoind`
//! binds a fixed RPC port (collisions across parallel tests would flake).

use std::{collections::BTreeSet, sync::Arc};

use bdk_bitcoind_rpc::bitcoincore_rpc;
use bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, Psbt, TapSighashType, Transaction, TxOut, Witness,
    XOnlyPublicKey, absolute,
    key::{Keypair, Secp256k1, TapTweak},
    secp256k1::{Message, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot,
    transaction::Version,
};
use bitcoind_async_client::{Client as BitcoinClient, traits::Reader};
use btc_tracker::cpfp::{
    self, BumpOutcome, BumpReason, CpfpContext, CpfpHandle, CpfpStrategy, InputSigner,
};
use operator_wallet::{NativeGeneralWallet, OperatorWallet, OperatorWalletConfig, sync::Backend};
use serial_test::serial;
use strata_bridge_connectors::{Connector, multi_anchor::MultiAnchor};
use strata_bridge_exec::cpfp_adapters::{BitcoindCpfpMempool, OperatorWalletCpfpAdapter};
use tokio::sync::RwLock;

/// Test fee target: well above the bridge protocol floor so the bump path fires.
const TEST_FEE_TARGET: u64 = 20;
/// Cap (`max_fee_rate`) for the package; well above the target.
const TEST_FEE_CAP: u64 = 100;
/// Bridge protocol floor lowered to 1 sat/vB for this test so a 20 sat/vB target unambiguously
/// triggers the bump.
const TEST_FLOOR: u64 = 1;
/// Fee rate used to fund the v3 parent. Independent of the package target — just needs to be
/// above min-relay so the parent on its own is mempool-valid.
const PARENT_FEE_RATE_SAT_PER_VB: u64 = 5;

/// `Fixed` fee source that always returns the same rate. Avoids depending on bitcoind's
/// estimatesmartfee (which returns 0 in a quiet regtest).
#[derive(Debug)]
struct FixedFeeSource(FeeRate);

impl cpfp::CpfpFeeSource for FixedFeeSource {
    fn estimate(
        &self,
    ) -> impl std::future::Future<Output = Result<FeeRate, cpfp::FeeSourceError>> + Send {
        let rate = self.0;
        async move { Ok(rate) }
    }
}

/// Boots `bitcoind`, mines coinbase maturity, and returns the node plus an async RPC client.
fn setup_bitcoind() -> (corepc_node::Node, BitcoinClient) {
    let bitcoind = corepc_node::Node::with_conf("bitcoind", &corepc_node::Conf::default())
        .expect("bitcoind must start");
    let address = bitcoind
        .client
        .new_address()
        .expect("address from bitcoind wallet");
    bitcoind
        .client
        .generate_to_address(101, &address)
        .expect("mine coinbase maturity");

    let cookie = bitcoind
        .params
        .get_cookie_values()
        .expect("read cookie")
        .expect("parse cookie");
    let auth = bitcoind_async_client::Auth::UserPass(cookie.user, cookie.password);
    let async_client = BitcoinClient::new(bitcoind.rpc_url(), auth, None, None, None)
        .expect("async rpc client must initialize");
    (bitcoind, async_client)
}

/// Spins up a sync `bitcoincore_rpc::Client` against the running node — needed by
/// `Backend::BitcoinCore` which doesn't accept the async client.
fn sync_rpc_client(bitcoind: &corepc_node::Node) -> bitcoincore_rpc::Client {
    let cookie_path = bitcoind.params.cookie_file.clone();
    let auth = bitcoincore_rpc::Auth::CookieFile(cookie_path);
    bitcoincore_rpc::Client::new(&bitcoind.rpc_url(), auth).expect("sync rpc client")
}

/// Asserts — via `getmempoolentry` on the child — that the mempool sees the `[parent, child]`
/// package paying at least [`TEST_FEE_TARGET`] sat/vB. This is what makes the e2e a *fee* test
/// rather than just a relay test: a package accepted while underpaying its target (a fee-math
/// regression) would still pass the mempool-presence and confirmation checks.
///
/// The slack is a few absolute sat, not a whole sat/vB. A sat/vB of slack sounds tight but is
/// worth hundreds of sat on a package this size, which is easily enough to hide a systematic
/// underpay — an earlier revision of this helper allowed exactly that, and the multi-anchor
/// case passed only because it was exercised at the single watchtower count that squeaked
/// under the tolerance. Integer truncation in the fee math is worth well under 1 sat total.
const PACKAGE_FEE_SLACK_SAT: u64 = 4;

fn assert_package_pays_target(bitcoind: &corepc_node::Node, child_txid: bitcoin::Txid) {
    use bitcoincore_rpc::RpcApi;
    let rpc = sync_rpc_client(bitcoind);
    let entry = rpc
        .get_mempool_entry(&child_txid)
        .expect("child must have a mempool entry");
    // The child's only in-mempool ancestor is the parent, so the ancestor aggregate (child
    // included) is exactly the package the bump submitted.
    let ancestor_fee_sat = entry.fees.ancestor.to_sat();
    let ancestor_vsize = entry.ancestor_size;
    let required = TEST_FEE_TARGET * ancestor_vsize;
    assert!(
        ancestor_fee_sat + PACKAGE_FEE_SLACK_SAT >= required,
        "package pays {ancestor_fee_sat} sat over {ancestor_vsize} vB = {:.2} sat/vB, \
         below the {TEST_FEE_TARGET} sat/vB target (needs {required} sat)",
        ancestor_fee_sat as f64 / ancestor_vsize as f64
    );
}

/// Constructs a `NativeGeneralWallet` keyed to `pubkey`, syncs it against `bitcoind`, and
/// wraps it in an `OperatorWallet`. Sends `funding_utxos` separate UTXOs of `funding_per_utxo`
/// each to the wallet's address so subsequent fundings (parent + child) draw from distinct
/// UTXOs without needing intra-test rescans.
async fn build_operator_wallet(
    bitcoind: &corepc_node::Node,
    pubkey: XOnlyPublicKey,
    funding_utxos: usize,
    funding_per_utxo: Amount,
) -> Arc<RwLock<OperatorWallet<NativeGeneralWallet>>> {
    let backend = Backend::BitcoinCore(Arc::new(sync_rpc_client(bitcoind)));
    let backend_clone = Backend::BitcoinCore(Arc::new(sync_rpc_client(bitcoind)));
    let general_wallet = NativeGeneralWallet::new(pubkey, Network::Regtest, backend);
    let config = OperatorWalletConfig::new(Amount::from_sat(330), Network::Regtest);
    let secp = Secp256k1::new();
    let reserved_secret = SecretKey::from_slice(&[0x42u8; 32]).expect("valid 32-byte scalar");
    let reserved_keypair = Keypair::from_secret_key(&secp, &reserved_secret);
    let (reserved_pubkey, _) = reserved_keypair.x_only_public_key();
    let mut wallet = OperatorWallet::new(
        general_wallet,
        reserved_pubkey,
        config,
        backend_clone,
        BTreeSet::new(),
    );

    let address = Address::p2tr(&secp, pubkey, None, Network::Regtest);

    for _ in 0..funding_utxos {
        bitcoind
            .client
            .send_to_address(&address, funding_per_utxo)
            .expect("send_to_address");
    }
    let miner_addr = bitcoind.client.new_address().expect("address");
    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine confirmation");

    wallet.sync().await.expect("wallet sync after funding");
    Arc::new(RwLock::new(wallet))
}

/// Builds a fully-signed v3 parent transaction with a 330-sat keyed-Taproot anchor output
/// keyed to `operator_pubkey`. Spends a wallet-selected UTXO; signed in-process with
/// `operator_keypair`.
async fn build_v3_parent(
    wallet: &Arc<RwLock<OperatorWallet<NativeGeneralWallet>>>,
    operator_keypair: Keypair,
    operator_pubkey: XOnlyPublicKey,
    parent_fee_rate: FeeRate,
) -> Transaction {
    let secp = Secp256k1::new();
    let anchor_script =
        Address::p2tr(&secp, operator_pubkey, None, Network::Regtest).script_pubkey();
    let unsigned_tx = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: Amount::from_sat(330),
            script_pubkey: anchor_script,
        }],
    };
    let funded = {
        let wallet = wallet.read().await;
        wallet
            .fund_v3_transaction(
                unsigned_tx,
                parent_fee_rate,
                operator_wallet::GeneralUtxoPolicy::ConfirmedOnly,
                operator_wallet::LeaseOwner::ClaimFundingRefill,
            )
            .await
            .expect("fund_v3_transaction (parent)")
    };
    // Commit the lease on the parent's funding inputs, exactly as every production executor
    // does once it publishes a parent. The inputs stay held until a sync observes the spend.
    // Without this, they return to the spendable set while the parent is still unbroadcast,
    // the CPFP child can select one of them, and `submitpackage` rejects the package with
    // "conflict-in-package".
    let (mut psbt, funding_lease) = funded.into_parts();
    funding_lease.commit();
    sign_funding_inputs(&mut psbt, operator_keypair, &[]).expect("sign parent funding inputs");
    finalize_to_tx(psbt)
}

/// Signs every PSBT input whose outpoint is NOT in `skip` as Taproot key-path with
/// `keypair` (BIP-341 tap-tweak with no merkle root), placing the resulting Schnorr signature
/// in `tap_key_sig`. Requires `witness_utxo` to be set on every input (BDK populates this).
fn sign_funding_inputs(psbt: &mut Psbt, keypair: Keypair, skip: &[OutPoint]) -> Result<(), String> {
    let secp = Secp256k1::new();
    let tweaked = keypair.tap_tweak(&secp, None);
    let tweaked_keypair = tweaked.to_keypair();

    let prevouts: Vec<TxOut> = psbt
        .inputs
        .iter()
        .enumerate()
        .map(|(i, input)| {
            input
                .witness_utxo
                .clone()
                .ok_or_else(|| format!("input {i}: witness_utxo not populated"))
        })
        .collect::<Result<_, _>>()?;

    let unsigned_tx = psbt.unsigned_tx.clone();
    let mut cache = SighashCache::new(&unsigned_tx);
    let prevouts_all = Prevouts::All(&prevouts);

    for i in 0..psbt.inputs.len() {
        let outpoint = unsigned_tx.input[i].previous_output;
        if skip.contains(&outpoint) {
            continue;
        }
        let sighash = cache
            .taproot_key_spend_signature_hash(i, &prevouts_all, TapSighashType::Default)
            .map_err(|e| format!("input {i}: sighash: {e:?}"))?;
        let msg = Message::from(sighash);
        let signature = secp.sign_schnorr_no_aux_rand(&msg, &tweaked_keypair);
        psbt.inputs[i].tap_key_sig = Some(taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        });
    }
    Ok(())
}

/// Transforms a PSBT with `tap_key_sig` set on every input into a final Transaction by
/// promoting each `tap_key_sig` to `final_script_witness` and calling `extract_tx`.
fn finalize_to_tx(mut psbt: Psbt) -> Transaction {
    for input in &mut psbt.inputs {
        if input.final_script_witness.is_some() {
            continue;
        }
        if let Some(sig) = input.tap_key_sig.take() {
            let mut witness = Witness::new();
            witness.push(sig.to_vec());
            input.final_script_witness = Some(witness);
        }
    }
    psbt.extract_tx().expect("extract_tx")
}

/// Builds an [`InputSigner`] that signs a Taproot key-path digest with the test's known
/// `keypair`, applying BIP-341 tap-tweak with an empty merkle root. In production the
/// anchor- and wallet-input signers go through different secret-service signers (musig2
/// signer vs. general-wallet signer) but in this test both keys are the same (`operator_pubkey`
/// — the wallet's descriptor key AND the anchor's internal key), so one closure suffices.
fn test_input_signer(keypair: Keypair) -> InputSigner {
    Arc::new(move |msg: Message| {
        let kp = keypair;
        Box::pin(async move {
            let tweaked = kp.tap_tweak(&Secp256k1::new(), None);
            let sig = Secp256k1::new().sign_schnorr_no_aux_rand(&msg, &tweaked.to_keypair());
            Ok(sig)
        })
    })
}

#[tokio::test]
#[serial]
async fn cpfp_e2e_against_bitcoind() {
    let (bitcoind, async_client) = setup_bitcoind();
    let async_client = Arc::new(async_client);

    // ── 1. Operator key + wallet ───────────────────────────────────────────
    let secp = Secp256k1::new();
    let operator_secret = SecretKey::from_slice(&[7u8; 32]).expect("valid 32-byte scalar");
    let operator_keypair = Keypair::from_secret_key(&secp, &operator_secret);
    let (operator_pubkey, _) = operator_keypair.x_only_public_key();

    // Fund three separate UTXOs so the parent and the child draw from distinct outputs.
    // (The wallet leases the parent's selected UTXO after `fund_v3_transaction`; without
    // additional UTXOs the child would fail at coin selection.)
    let wallet = build_operator_wallet(
        &bitcoind,
        operator_pubkey,
        3,
        Amount::from_btc(0.5).unwrap(),
    )
    .await;

    // ── 2. Build a fully-signed v3 parent with a keyed-Taproot anchor ──────
    let parent_fee_rate = FeeRate::from_sat_per_vb(PARENT_FEE_RATE_SAT_PER_VB).unwrap();
    let parent = build_v3_parent(&wallet, operator_keypair, operator_pubkey, parent_fee_rate).await;
    assert_eq!(parent.version.0, 3, "parent must be v3 (TRUC)");
    let parent_txid = parent.compute_txid();
    let anchor_vout: u32 = parent
        .output
        .iter()
        .position(|o| {
            o.value == Amount::from_sat(330)
                && o.script_pubkey
                    == Address::p2tr(&secp, operator_pubkey, None, Network::Regtest).script_pubkey()
        })
        .expect("anchor output must exist on the parent we just built")
        as u32;
    let parent_fee = parent_fee_rate
        .fee_vb(parent.vsize() as u64)
        .expect("parent fee fits in Amount");

    // ── 3. CpfpContext with real components ────────────────────────────────
    //
    // Production wires `OperatorWalletCpfpAdapter` directly (it returns unsigned PSBTs;
    // perform_bump signs every input via `anchor_input_signer` / `wallet_input_signer`).
    // No test-only wrapper is needed.
    let cpfp_wallet = Arc::new(OperatorWalletCpfpAdapter::new(
        wallet.clone(),
        operator_pubkey,
    ));
    let cpfp_submitter = Arc::new(BitcoindCpfpMempool::new(async_client.clone()));
    let fee_source = Arc::new(FixedFeeSource(
        FeeRate::from_sat_per_vb(TEST_FEE_TARGET).unwrap(),
    ));
    let max_fee_rate = FeeRate::from_sat_per_vb(TEST_FEE_CAP).unwrap();
    let bridge_protocol_floor = FeeRate::from_sat_per_vb(TEST_FLOOR).unwrap();

    let anchor_input_signer = test_input_signer(operator_keypair);
    let wallet_input_signer = test_input_signer(operator_keypair);

    let ctx = CpfpContext {
        wallet: cpfp_wallet,
        multi_anchor_signer: test_input_signer(operator_keypair),
        fee_source,
        anchor_input_signer,
        wallet_input_signer,
        max_fee_rate,
        mempool: cpfp_submitter,
    };

    // ── 4. perform_bump → submits [parent, child] package ──────────────────
    let strategy = CpfpStrategy::AnchorBearing {
        anchor_vout,
        anchor_internal_key: operator_pubkey,
        parent_fee,
    };
    let mut handle = CpfpHandle::default();
    let bumped = cpfp::perform_bump(
        &ctx,
        &parent,
        strategy,
        &mut handle,
        bridge_protocol_floor,
        BumpReason::NewJob,
    )
    .await
    .expect("perform_bump must succeed end-to-end");
    assert_eq!(
        bumped,
        BumpOutcome::Submitted,
        "expected the bump to fire (target {TEST_FEE_TARGET} sat/vB > floor)"
    );

    // ── 5. Assert: mempool contains parent + child ─────────────────────────
    let child_txid = handle.last_child_txid.expect("child txid populated");
    let _ = async_client
        .get_raw_transaction_verbosity_one(&parent_txid)
        .await
        .expect("parent must be in mempool or chain");
    let _ = async_client
        .get_raw_transaction_verbosity_one(&child_txid)
        .await
        .expect("child must be in mempool");

    assert_package_pays_target(&bitcoind, child_txid);

    // ── 6. Mine a block and assert both confirm in it ──────────────────────
    //
    // `bitcoind` is started without `-txindex`, so `getrawtransaction` can't look up
    // confirmed-and-pruned txs by txid alone. Read the new block directly and assert both
    // txids are in its txdata.
    let miner_addr = bitcoind.client.new_address().expect("new address");
    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine block");

    let tip_height = async_client.get_block_count().await.expect("block count");
    let tip_hash = async_client
        .get_block_hash(tip_height)
        .await
        .expect("tip hash");
    let tip_block = async_client.get_block(&tip_hash).await.expect("tip block");
    let confirmed_txids: BTreeSet<_> = tip_block
        .txdata
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect();
    assert!(
        confirmed_txids.contains(&parent_txid),
        "parent must confirm in the mined block"
    );
    assert!(
        confirmed_txids.contains(&child_txid),
        "child must confirm in the same block as parent"
    );
}

/// Builds a fully-signed v3 parent whose single output is operator-owned (no anchor) —
/// mirrors the shape of cooperative_payout / uncontested_payout / unstaking txs that use
/// [`CpfpStrategy::ParentTxCombined`] in production.
async fn build_v3_payout_parent(
    wallet: &Arc<RwLock<OperatorWallet<NativeGeneralWallet>>>,
    operator_keypair: Keypair,
    operator_pubkey: XOnlyPublicKey,
    parent_fee_rate: FeeRate,
    payout_value: Amount,
) -> Transaction {
    let secp = Secp256k1::new();
    let payout_script =
        Address::p2tr(&secp, operator_pubkey, None, Network::Regtest).script_pubkey();
    let unsigned_tx = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![TxOut {
            value: payout_value,
            script_pubkey: payout_script,
        }],
    };
    let funded = {
        let wallet = wallet.read().await;
        wallet
            .fund_v3_transaction(
                unsigned_tx,
                parent_fee_rate,
                operator_wallet::GeneralUtxoPolicy::ConfirmedOnly,
                operator_wallet::LeaseOwner::ClaimFundingRefill,
            )
            .await
            .expect("fund_v3_transaction (payout parent)")
    };
    // Commit the lease on the parent's funding inputs, exactly as every production executor
    // does once it publishes a parent. The inputs stay held until a sync observes the spend.
    // Without this, they return to the spendable set while the parent is still unbroadcast,
    // the CPFP child can select one of them, and `submitpackage` rejects the package with
    // "conflict-in-package".
    let (mut psbt, funding_lease) = funded.into_parts();
    funding_lease.commit();
    sign_funding_inputs(&mut psbt, operator_keypair, &[])
        .expect("sign payout parent funding inputs");
    finalize_to_tx(psbt)
}

/// E2E test for [`CpfpStrategy::ParentTxCombined`]: a v3 parent whose only output is an
/// operator-owned payout, plus a CPFP child that spends that output (via `add_foreign_utxo`)
/// + a wallet funding input, drained back to the wallet. Validates that the broken
/// `manually_selected_only + add_utxo` path (which would fail on a not-yet-broadcast parent)
/// is no longer in use and that the unified foreign-UTXO machinery in the adapter handles
/// PayoutCombined correctly against real `bitcoind`.
#[tokio::test]
#[serial]
async fn cpfp_e2e_parent_tx_combined_against_bitcoind() {
    let (bitcoind, async_client) = setup_bitcoind();
    let async_client = Arc::new(async_client);

    let secp = Secp256k1::new();
    let operator_secret = SecretKey::from_slice(&[11u8; 32]).expect("valid 32-byte scalar");
    let operator_keypair = Keypair::from_secret_key(&secp, &operator_secret);
    let (operator_pubkey, _) = operator_keypair.x_only_public_key();

    // Fund three UTXOs: one funds the payout parent, one funds the CPFP child, one spare.
    let wallet = build_operator_wallet(
        &bitcoind,
        operator_pubkey,
        3,
        Amount::from_btc(0.5).unwrap(),
    )
    .await;

    // Build a v3 payout parent: single operator-owned output, no anchor. This mirrors the
    // structure of cooperative_payout / uncontested_payout / unstaking txs in production.
    let parent_fee_rate = FeeRate::from_sat_per_vb(PARENT_FEE_RATE_SAT_PER_VB).unwrap();
    let parent = build_v3_payout_parent(
        &wallet,
        operator_keypair,
        operator_pubkey,
        parent_fee_rate,
        Amount::from_btc(0.25).unwrap(),
    )
    .await;
    assert_eq!(parent.version.0, 3, "payout parent must be v3 (TRUC)");
    let parent_txid = parent.compute_txid();
    let parent_fee = parent_fee_rate
        .fee_vb(parent.vsize() as u64)
        .expect("parent fee fits in Amount");

    // The payout outpoint is vout 0 of the parent — the operator-owned output.
    let payout_outpoint = OutPoint {
        txid: parent_txid,
        vout: 0,
    };

    // CpfpContext, mirroring production wiring. `operator_general_pubkey` passed to the
    // adapter so it can construct the foreign-UTXO PSBT input with the right
    // `tap_internal_key` when CPFPing a PayoutCombined parent.
    let cpfp_wallet = Arc::new(OperatorWalletCpfpAdapter::new(
        wallet.clone(),
        operator_pubkey,
    ));
    let cpfp_submitter = Arc::new(BitcoindCpfpMempool::new(async_client.clone()));
    let fee_source = Arc::new(FixedFeeSource(
        FeeRate::from_sat_per_vb(TEST_FEE_TARGET).unwrap(),
    ));
    let max_fee_rate = FeeRate::from_sat_per_vb(TEST_FEE_CAP).unwrap();
    let bridge_protocol_floor = FeeRate::from_sat_per_vb(TEST_FLOOR).unwrap();

    let anchor_input_signer = test_input_signer(operator_keypair);
    let wallet_input_signer = test_input_signer(operator_keypair);

    let ctx = CpfpContext {
        wallet: cpfp_wallet,
        multi_anchor_signer: test_input_signer(operator_keypair),
        fee_source,
        anchor_input_signer,
        wallet_input_signer,
        max_fee_rate,
        mempool: cpfp_submitter,
    };

    let strategy = CpfpStrategy::ParentTxCombined {
        payout_outpoint,
        parent_fee,
    };
    let mut handle = CpfpHandle::default();
    let bumped = cpfp::perform_bump(
        &ctx,
        &parent,
        strategy,
        &mut handle,
        bridge_protocol_floor,
        BumpReason::NewJob,
    )
    .await
    .expect("perform_bump must succeed end-to-end for ParentTxCombined");
    assert_eq!(
        bumped,
        BumpOutcome::Submitted,
        "expected the bump to fire (target {TEST_FEE_TARGET} sat/vB > floor)"
    );

    let child_txid = handle.last_child_txid.expect("child txid populated");
    let _ = async_client
        .get_raw_transaction_verbosity_one(&parent_txid)
        .await
        .expect("payout parent must be in mempool");
    let _ = async_client
        .get_raw_transaction_verbosity_one(&child_txid)
        .await
        .expect("child must be in mempool");

    assert_package_pays_target(&bitcoind, child_txid);

    let miner_addr = bitcoind.client.new_address().expect("new address");
    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine block");

    let tip_height = async_client.get_block_count().await.expect("block count");
    let tip_hash = async_client
        .get_block_hash(tip_height)
        .await
        .expect("tip hash");
    let tip_block = async_client.get_block(&tip_hash).await.expect("tip block");
    let confirmed_txids: BTreeSet<_> = tip_block
        .txdata
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect();
    assert!(
        confirmed_txids.contains(&parent_txid),
        "payout parent must confirm in the mined block"
    );
    assert!(
        confirmed_txids.contains(&child_txid),
        "PayoutCombined child must confirm in the same block as the parent"
    );
}

/// Builds a v3 parent shaped like a withdrawal-fulfillment or slash tx: an OP_RETURN-ish
/// "header" output, a payout output to a non-operator key (the "user" payout / a different
/// watchtower), and a payout output to the operator's general script (the BDK change / the
/// calling watchtower's slash share). The third one is the CPFP hook the production helper
/// would discover via `CpfpKind::InferGeneralPayout`.
async fn build_v3_mixed_parent(
    wallet: &Arc<RwLock<OperatorWallet<NativeGeneralWallet>>>,
    operator_keypair: Keypair,
    operator_pubkey: XOnlyPublicKey,
    other_pubkey: XOnlyPublicKey,
    parent_fee_rate: FeeRate,
    other_value: Amount,
    operator_value: Amount,
) -> Transaction {
    let secp = Secp256k1::new();
    let operator_script =
        Address::p2tr(&secp, operator_pubkey, None, Network::Regtest).script_pubkey();
    let other_script = Address::p2tr(&secp, other_pubkey, None, Network::Regtest).script_pubkey();
    let unsigned_tx = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![
            // vout 0: a non-operator output (the "user payout" or "other watchtower share")
            TxOut {
                value: other_value,
                script_pubkey: other_script,
            },
            // vout 1: the operator-owned output (the BDK change / the calling watchtower's
            // own slash share). This is what `InferGeneralPayout` should discover.
            TxOut {
                value: operator_value,
                script_pubkey: operator_script,
            },
        ],
    };
    let funded = {
        let wallet = wallet.read().await;
        wallet
            .fund_v3_transaction(
                unsigned_tx,
                parent_fee_rate,
                operator_wallet::GeneralUtxoPolicy::ConfirmedOnly,
                operator_wallet::LeaseOwner::ClaimFundingRefill,
            )
            .await
            .expect("fund_v3_transaction (mixed parent)")
    };
    // Commit the lease on the parent's funding inputs, exactly as every production executor
    // does once it publishes a parent. The inputs stay held until a sync observes the spend.
    // Without this, they return to the spendable set while the parent is still unbroadcast,
    // the CPFP child can select one of them, and `submitpackage` rejects the package with
    // "conflict-in-package".
    let (mut psbt, funding_lease) = funded.into_parts();
    funding_lease.commit();
    sign_funding_inputs(&mut psbt, operator_keypair, &[])
        .expect("sign mixed parent funding inputs");
    finalize_to_tx(psbt)
}

/// E2E test for the `CpfpKind::InferGeneralPayout`-shaped path: a v3 parent with a mix of
/// operator-owned and non-operator outputs, where the production helper picks the operator
/// output by script match (no fixed vout). This exercises the WFT / stake-funding-change /
/// slash classification path against real `bitcoind`.
#[tokio::test]
#[serial]
async fn cpfp_e2e_infer_general_payout_against_bitcoind() {
    let (bitcoind, async_client) = setup_bitcoind();
    let async_client = Arc::new(async_client);

    let secp = Secp256k1::new();
    let operator_secret = SecretKey::from_slice(&[13u8; 32]).expect("valid 32-byte scalar");
    let operator_keypair = Keypair::from_secret_key(&secp, &operator_secret);
    let (operator_pubkey, _) = operator_keypair.x_only_public_key();

    // A second key for the non-operator output — simulates the user destination on a WFT
    // or another watchtower's payout on slash.
    let other_secret = SecretKey::from_slice(&[99u8; 32]).expect("valid 32-byte scalar");
    let other_keypair = Keypair::from_secret_key(&secp, &other_secret);
    let (other_pubkey, _) = other_keypair.x_only_public_key();

    let wallet = build_operator_wallet(
        &bitcoind,
        operator_pubkey,
        3,
        Amount::from_btc(0.5).unwrap(),
    )
    .await;

    let parent_fee_rate = FeeRate::from_sat_per_vb(PARENT_FEE_RATE_SAT_PER_VB).unwrap();
    let parent = build_v3_mixed_parent(
        &wallet,
        operator_keypair,
        operator_pubkey,
        other_pubkey,
        parent_fee_rate,
        Amount::from_btc(0.1).unwrap(),  // non-operator payout
        Amount::from_btc(0.15).unwrap(), // operator-owned payout (CPFP hook)
    )
    .await;
    assert_eq!(parent.version.0, 3, "mixed parent must be v3 (TRUC)");
    let parent_txid = parent.compute_txid();
    let parent_fee = parent_fee_rate
        .fee_vb(parent.vsize() as u64)
        .expect("parent fee fits in Amount");

    // Manually replicate what `first_general_payout_outpoint` does: find vout matching the
    // operator's P2TR script. In production, `chain::publish_signed_transaction` with
    // `CpfpKind::InferGeneralPayout` performs this scan; here we do it explicitly so the
    // test can call `perform_bump` directly with the resolved strategy.
    let operator_script =
        Address::p2tr(&secp, operator_pubkey, None, Network::Regtest).script_pubkey();
    let operator_vout = parent
        .output
        .iter()
        .position(|o| o.script_pubkey == operator_script)
        .expect("the operator-owned output must be present at some vout")
        as u32;
    let payout_outpoint = OutPoint {
        txid: parent_txid,
        vout: operator_vout,
    };
    // Confirm we found vout 1 (the second output we added) — the "other" payout is at
    // vout 0, our operator output is at vout 1. If BDK added a change output, it'd be vout
    // 2+ (but since the parent's total output value already covers most of the input, the
    // change would also match our script — and `first_general_payout_outpoint` picks the
    // FIRST match, which is still operator-owned). This confirms the scan returns a valid
    // operator-owned outpoint.
    assert_eq!(
        operator_vout, 1,
        "operator-owned output must be at vout 1 (the second output we added)"
    );

    let cpfp_wallet = Arc::new(OperatorWalletCpfpAdapter::new(
        wallet.clone(),
        operator_pubkey,
    ));
    let cpfp_submitter = Arc::new(BitcoindCpfpMempool::new(async_client.clone()));
    let fee_source = Arc::new(FixedFeeSource(
        FeeRate::from_sat_per_vb(TEST_FEE_TARGET).unwrap(),
    ));
    let max_fee_rate = FeeRate::from_sat_per_vb(TEST_FEE_CAP).unwrap();
    let bridge_protocol_floor = FeeRate::from_sat_per_vb(TEST_FLOOR).unwrap();
    let anchor_input_signer = test_input_signer(operator_keypair);
    let wallet_input_signer = test_input_signer(operator_keypair);

    let ctx = CpfpContext {
        wallet: cpfp_wallet,
        multi_anchor_signer: test_input_signer(operator_keypair),
        fee_source,
        anchor_input_signer,
        wallet_input_signer,
        max_fee_rate,
        mempool: cpfp_submitter,
    };

    let strategy = CpfpStrategy::ParentTxCombined {
        payout_outpoint,
        parent_fee,
    };
    let mut handle = CpfpHandle::default();
    let bumped = cpfp::perform_bump(
        &ctx,
        &parent,
        strategy,
        &mut handle,
        bridge_protocol_floor,
        BumpReason::NewJob,
    )
    .await
    .expect("perform_bump must succeed end-to-end for InferGeneralPayout shape");
    assert_eq!(
        bumped,
        BumpOutcome::Submitted,
        "bump must fire at target above floor"
    );

    let child_txid = handle.last_child_txid.expect("child txid populated");
    let _ = async_client
        .get_raw_transaction_verbosity_one(&parent_txid)
        .await
        .expect("mixed parent must be in mempool");
    let _ = async_client
        .get_raw_transaction_verbosity_one(&child_txid)
        .await
        .expect("InferGeneralPayout child must be in mempool");

    assert_package_pays_target(&bitcoind, child_txid);

    let miner_addr = bitcoind.client.new_address().expect("new address");
    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine block");

    let tip_height = async_client.get_block_count().await.expect("block count");
    let tip_hash = async_client
        .get_block_hash(tip_height)
        .await
        .expect("tip hash");
    let tip_block = async_client.get_block(&tip_hash).await.expect("tip block");
    let confirmed_txids: BTreeSet<_> = tip_block
        .txdata
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect();
    assert!(
        confirmed_txids.contains(&parent_txid),
        "mixed parent must confirm in the mined block"
    );
    assert!(
        confirmed_txids.contains(&child_txid),
        "InferGeneralPayout child must confirm in the same block as the parent"
    );
}

/// Builds a fully-signed v3 parent whose 330-sat anchor output is a real [`MultiAnchor`]
/// connector output — a Taproot script tree with one `<wt_key> OP_CHECKSIG` leaf per
/// watchtower over an unspendable internal key, exactly as contest / bridge-proof-timeout
/// transactions carry it in production.
async fn build_v3_multi_anchor_parent(
    wallet: &Arc<RwLock<OperatorWallet<NativeGeneralWallet>>>,
    operator_keypair: Keypair,
    anchor: &MultiAnchor,
    parent_fee_rate: FeeRate,
) -> Transaction {
    let unsigned_tx = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![],
        output: vec![anchor.tx_out()],
    };
    let funded = {
        let wallet = wallet.read().await;
        wallet
            .fund_v3_transaction(
                unsigned_tx,
                parent_fee_rate,
                operator_wallet::GeneralUtxoPolicy::ConfirmedOnly,
                operator_wallet::LeaseOwner::ClaimFundingRefill,
            )
            .await
            .expect("fund_v3_transaction (multi-anchor parent)")
    };
    // Commit the lease on the parent's funding inputs, exactly as every production executor
    // does once it publishes a parent. The inputs stay held until a sync observes the spend.
    // Without this, they return to the spendable set while the parent is still unbroadcast,
    // the CPFP child can select one of them, and `submitpackage` rejects the package with
    // "conflict-in-package".
    let (mut psbt, funding_lease) = funded.into_parts();
    funding_lease.commit();
    sign_funding_inputs(&mut psbt, operator_keypair, &[])
        .expect("sign multi-anchor parent funding inputs");
    finalize_to_tx(psbt)
}

/// Builds an [`InputSigner`] that signs with the raw (untweaked) keypair — mirroring the
/// production multi-anchor signer (secret-service `sign_no_tweak`): a Taproot script-path
/// signature verifies against the key inside the leaf script, so no output-key tweak is
/// applied.
fn test_untweaked_input_signer(keypair: Keypair) -> InputSigner {
    Arc::new(move |msg: Message| {
        let kp = keypair;
        Box::pin(async move {
            let sig = Secp256k1::new().sign_schnorr_no_aux_rand(&msg, &kp);
            Ok(sig)
        })
    })
}

/// E2E test for the `MultiAnchorBearing` script-path CPFP pipeline against real `bitcoind`.
///
/// This is the consensus-level check the unit tests can't provide: the script-path sighash
/// (leaf-committed), the untweaked leaf signature, and the `[sig, leaf_script,
/// control_block]` witness ordering are all validated by bitcoind's script interpreter — a
/// wrong tweak, a wrong leaf hash, or a swapped witness item is an outright package
/// rejection, not a silently-degraded assertion.
#[tokio::test]
#[serial]
async fn cpfp_e2e_multi_anchor_against_bitcoind() {
    let (bitcoind, async_client) = setup_bitcoind();
    let async_client = Arc::new(async_client);

    // ── 1. Keys: funding operator + two watchtowers (we are watchtower 1) ──
    let secp = Secp256k1::new();
    let operator_secret = SecretKey::from_slice(&[7u8; 32]).expect("valid 32-byte scalar");
    let operator_keypair = Keypair::from_secret_key(&secp, &operator_secret);
    let (operator_pubkey, _) = operator_keypair.x_only_public_key();

    // Seven watchtowers, and we take a middle leaf — not leaf 0 (which an off-by-one that
    // maps everything to zero would still satisfy) and not the last. The count matters as
    // much as the index: a deeper tree means a longer control block and so a heavier child,
    // which is exactly what a size predictor blind to anchor shape gets wrong. An earlier
    // revision of this test used two watchtowers, the one count shallow enough that the
    // resulting underpay slipped under the fee assertion.
    const N_WATCHTOWERS: u8 = 7;
    const OUR_SLOT: usize = 3;
    let wt_keypairs: Vec<Keypair> = (0..N_WATCHTOWERS)
        .map(|i| {
            let secret = SecretKey::from_slice(&[11 + i; 32]).expect("valid 32-byte scalar");
            Keypair::from_secret_key(&secp, &secret)
        })
        .collect();
    let wt_pubkeys: Vec<XOnlyPublicKey> = wt_keypairs
        .iter()
        .map(|kp| kp.x_only_public_key().0)
        .collect();
    let our_wt_keypair = wt_keypairs[OUR_SLOT];

    let anchor = MultiAnchor::new(Network::Regtest, wt_pubkeys, Amount::from_sat(330));

    let wallet = build_operator_wallet(
        &bitcoind,
        operator_pubkey,
        3,
        Amount::from_btc(0.5).unwrap(),
    )
    .await;

    // ── 2. v3 parent bearing the multi-anchor output ───────────────────────
    let parent_fee_rate = FeeRate::from_sat_per_vb(PARENT_FEE_RATE_SAT_PER_VB).unwrap();
    let parent =
        build_v3_multi_anchor_parent(&wallet, operator_keypair, &anchor, parent_fee_rate).await;
    assert_eq!(parent.version.0, 3, "parent must be v3 (TRUC)");
    let parent_txid = parent.compute_txid();
    let anchor_vout = parent
        .output
        .iter()
        .position(|o| o.script_pubkey == anchor.script_pubkey())
        .expect("multi-anchor output must exist on the parent") as u32;
    let parent_fee = parent_fee_rate
        .fee_vb(parent.vsize() as u64)
        .expect("parent fee fits in Amount");

    // ── 3. Our leaf + control block, as the SM duty would carry them ───────
    let leaf_script = anchor.leaf_scripts()[OUR_SLOT].clone();
    let control_block = anchor
        .spend_info()
        .control_block(&(leaf_script.clone(), taproot::LeafVersion::TapScript))
        .expect("control block for our leaf");

    // ── 4. CpfpContext: untweaked signer on the multi-anchor slot ──────────
    //
    // The key-path anchor signer is wired to fail: a `MultiAnchorBearing` bump must never
    // consult it, so any routing regression surfaces as a hard test failure here too.
    let anchor_input_signer: InputSigner = Arc::new(move |_msg: Message| {
        Box::pin(async move {
            Err(cpfp::SignerError(
                "anchor_input_signer must not be called for a MultiAnchorBearing bump".into(),
            ))
        })
    });
    let ctx = CpfpContext {
        wallet: Arc::new(OperatorWalletCpfpAdapter::new(
            wallet.clone(),
            operator_pubkey,
        )),
        multi_anchor_signer: test_untweaked_input_signer(our_wt_keypair),
        fee_source: Arc::new(FixedFeeSource(
            FeeRate::from_sat_per_vb(TEST_FEE_TARGET).unwrap(),
        )),
        anchor_input_signer,
        wallet_input_signer: test_input_signer(operator_keypair),
        max_fee_rate: FeeRate::from_sat_per_vb(TEST_FEE_CAP).unwrap(),
        mempool: Arc::new(BitcoindCpfpMempool::new(async_client.clone())),
    };

    // ── 5. perform_bump → [parent, child] package via the script path ──────
    let strategy = CpfpStrategy::MultiAnchorBearing {
        anchor_vout,
        leaf_script,
        control_block,
        parent_fee,
    };
    let mut handle = CpfpHandle::default();
    let bumped = cpfp::perform_bump(
        &ctx,
        &parent,
        strategy,
        &mut handle,
        FeeRate::from_sat_per_vb(TEST_FLOOR).unwrap(),
        BumpReason::NewJob,
    )
    .await
    .expect("perform_bump must succeed end-to-end for MultiAnchorBearing");
    assert_eq!(
        bumped,
        BumpOutcome::Submitted,
        "bump must fire at target above floor"
    );

    // ── 6. Mempool + package feerate + confirmation ────────────────────────
    let child_txid = handle.last_child_txid.expect("child txid populated");
    let _ = async_client
        .get_raw_transaction_verbosity_one(&parent_txid)
        .await
        .expect("multi-anchor parent must be in mempool");
    let _ = async_client
        .get_raw_transaction_verbosity_one(&child_txid)
        .await
        .expect("multi-anchor child must be in mempool");

    assert_package_pays_target(&bitcoind, child_txid);

    let miner_addr = bitcoind.client.new_address().expect("new address");
    bitcoind
        .client
        .generate_to_address(1, &miner_addr)
        .expect("mine block");

    let tip_height = async_client.get_block_count().await.expect("block count");
    let tip_hash = async_client
        .get_block_hash(tip_height)
        .await
        .expect("tip hash");
    let tip_block = async_client.get_block(&tip_hash).await.expect("tip block");
    let confirmed_txids: BTreeSet<_> = tip_block
        .txdata
        .iter()
        .map(bitcoin::Transaction::compute_txid)
        .collect();
    assert!(
        confirmed_txids.contains(&parent_txid),
        "multi-anchor parent must confirm in the mined block"
    );
    assert!(
        confirmed_txids.contains(&child_txid),
        "multi-anchor child must confirm in the same block as the parent"
    );
}

/// Two watchtowers bump the same `MultiAnchor`, as they do in production.
///
/// The first one wins the anchor. The second one must then skip quietly rather than pay to
/// lose: it reads the spend state of the anchor, sees a package already at target, and returns
/// without building or signing. Every watchtower of a graph holds a leaf on the same anchor, so
/// without this the losers rebuild and resubmit on every trigger until the parent confirms.
///
/// The test also pins the rejection that bitcoind produces when the check is bypassed. That
/// string is what `SubmitPackageError::is_replacement_contention` matches, and matching on a
/// message is only safe while a test holds it against a live node.
#[tokio::test]
#[serial]
async fn cpfp_e2e_multi_anchor_contention_is_quiet() {
    let (bitcoind, async_client) = setup_bitcoind();
    let async_client = Arc::new(async_client);
    let secp = Secp256k1::new();
    let operator_secret = SecretKey::from_slice(&[7u8; 32]).expect("valid 32-byte scalar");
    let operator_keypair = Keypair::from_secret_key(&secp, &operator_secret);
    let (operator_pubkey, _) = operator_keypair.x_only_public_key();

    const N_WATCHTOWERS: u8 = 3;
    let wt_keypairs: Vec<Keypair> = (0..N_WATCHTOWERS)
        .map(|i| {
            let secret = SecretKey::from_slice(&[11 + i; 32]).expect("valid 32-byte scalar");
            Keypair::from_secret_key(&secp, &secret)
        })
        .collect();
    let wt_pubkeys: Vec<XOnlyPublicKey> = wt_keypairs
        .iter()
        .map(|kp| kp.x_only_public_key().0)
        .collect();
    let anchor = MultiAnchor::new(Network::Regtest, wt_pubkeys, Amount::from_sat(330));

    let wallet = build_operator_wallet(
        &bitcoind,
        operator_pubkey,
        6,
        Amount::from_btc(0.5).unwrap(),
    )
    .await;
    let parent_fee_rate = FeeRate::from_sat_per_vb(PARENT_FEE_RATE_SAT_PER_VB).unwrap();
    let parent =
        build_v3_multi_anchor_parent(&wallet, operator_keypair, &anchor, parent_fee_rate).await;
    let anchor_vout = parent
        .output
        .iter()
        .position(|o| o.script_pubkey == anchor.script_pubkey())
        .expect("multi-anchor output must exist") as u32;
    let parent_fee = parent_fee_rate
        .fee_vb(parent.vsize() as u64)
        .expect("parent fee fits in Amount");

    // One context per watchtower, each signing with its own leaf.
    let context_for = |slot: usize| {
        let leaf_script = anchor.leaf_scripts()[slot].clone();
        let control_block = anchor
            .spend_info()
            .control_block(&(leaf_script.clone(), taproot::LeafVersion::TapScript))
            .expect("control block for the leaf of this watchtower");
        let ctx = CpfpContext {
            wallet: Arc::new(OperatorWalletCpfpAdapter::new(
                wallet.clone(),
                operator_pubkey,
            )),
            multi_anchor_signer: test_untweaked_input_signer(wt_keypairs[slot]),
            fee_source: Arc::new(FixedFeeSource(
                FeeRate::from_sat_per_vb(TEST_FEE_TARGET).unwrap(),
            )),
            anchor_input_signer: test_input_signer(operator_keypair),
            wallet_input_signer: test_input_signer(operator_keypair),
            max_fee_rate: FeeRate::from_sat_per_vb(TEST_FEE_CAP).unwrap(),
            mempool: Arc::new(BitcoindCpfpMempool::new(async_client.clone())),
        };
        let strategy = CpfpStrategy::MultiAnchorBearing {
            anchor_vout,
            leaf_script,
            control_block,
            parent_fee,
        };
        (ctx, strategy)
    };

    // Watchtower 0 takes the anchor.
    let (ctx0, strategy0) = context_for(0);
    let mut handle0 = CpfpHandle::default();
    let bumped = cpfp::perform_bump(
        &ctx0,
        &parent,
        strategy0,
        &mut handle0,
        FeeRate::from_sat_per_vb(TEST_FLOOR).unwrap(),
        BumpReason::NewJob,
    )
    .await
    .expect("the first watchtower must win the anchor");
    assert_eq!(
        bumped,
        BumpOutcome::Submitted,
        "the first bump must submit a package"
    );

    // Watchtower 1 now sees the anchor taken at target, and skips.
    let (ctx1, strategy1) = context_for(1);
    let mut handle1 = CpfpHandle::default();
    let bumped = cpfp::perform_bump(
        &ctx1,
        &parent,
        strategy1,
        &mut handle1,
        FeeRate::from_sat_per_vb(TEST_FLOOR).unwrap(),
        BumpReason::NewBlock,
    )
    .await
    .expect("a lost anchor is not an error");
    assert_eq!(
        bumped,
        BumpOutcome::ParentIsLive,
        "the second watchtower must stand down, and it must report that the first \
         watchtower's child already carries the parent"
    );
    assert!(
        handle1.last_child_txid.is_none(),
        "a skipping watchtower must not build or sign a child"
    );

    // Pin the rejection that the skip avoids.
    //
    // The skip works, so no watchtower reaches the submission any more. Reproduce what one
    // without the check meets by reporting the anchor as unspent while leaving the submission
    // real. This is the only way to hold the bitcoind message that
    // `is_replacement_contention` matches against a live node.
    let (ctx2, strategy2) = context_for(2);
    let ctx2 = CpfpContext {
        wallet: ctx2.wallet,
        multi_anchor_signer: ctx2.multi_anchor_signer,
        fee_source: ctx2.fee_source,
        anchor_input_signer: ctx2.anchor_input_signer,
        wallet_input_signer: ctx2.wallet_input_signer,
        max_fee_rate: ctx2.max_fee_rate,
        mempool: Arc::new(BlindToSpends(BitcoindCpfpMempool::new(
            async_client.clone(),
        ))),
    };
    let mut handle2 = CpfpHandle::default();
    let forced = cpfp::perform_bump(
        &ctx2,
        &parent,
        strategy2,
        &mut handle2,
        FeeRate::from_sat_per_vb(TEST_FLOOR).unwrap(),
        BumpReason::NewBlock,
    )
    .await;

    let err = forced.expect_err("a same-target child cannot displace the winner");
    assert!(
        err.is_replacement_contention(),
        "a lost race must classify as contention, not as a fault: {err}"
    );
}

/// Wraps the real mempool adapter and reports every anchor as unspent.
///
/// Submission stays real. Only the pre-build check is blinded, so a bump proceeds to the point
/// where bitcoind itself rejects it.
#[derive(Debug)]
struct BlindToSpends(BitcoindCpfpMempool);

impl cpfp::CpfpMempool for BlindToSpends {
    fn submit_package(
        &self,
        txs: &[Transaction],
    ) -> impl std::future::Future<
        Output = Result<
            btc_tracker::submitpackage::SubmitPackageSummary,
            btc_tracker::submitpackage::SubmitPackageError,
        >,
    > + Send {
        self.0.submit_package(txs)
    }

    async fn anchor_spend_state(
        &self,
        _anchor: OutPoint,
    ) -> Result<cpfp::AnchorSpendState, cpfp::MempoolError> {
        Ok(cpfp::AnchorSpendState::Unspent)
    }
}
