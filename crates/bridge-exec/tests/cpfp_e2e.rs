#![allow(unused_crate_dependencies)]
//! End-to-end CPFP regression test against a real `bitcoind` (regtest, via `corepc-node`).
//!
//! A `[parent, child]` v3 package is accepted by `bitcoind`'s `submitpackage` RPC, and the package
//! confirms when a block is mined.
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
//! The wallet is descriptor-only: it returns unsigned PSBTs. Production code
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

use async_trait::async_trait;
use bdk_bitcoind_rpc::bitcoincore_rpc;
use bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, Psbt, TapSighashType, Transaction, TxOut, Txid,
    Witness, XOnlyPublicKey,
    key::{Keypair, Secp256k1, TapTweak},
    secp256k1::{Message, SecretKey},
    sighash::{Prevouts, SighashCache},
    taproot,
};
use bitcoind_async_client::{
    Client as BitcoinClient,
    traits::{Broadcaster, Reader},
};
use btc_tracker::cpfp::{BumpOutcome, CpfpStrategy, DeadlineClass, FirstBump};
use operator_wallet::{
    GeneralCustody, GeneralUtxoPolicy, OperatorWallet, OperatorWalletConfig, sync::Backend,
    test_utils::MemoryStore,
};
use serial_test::serial;
use strata_bridge_connectors::{Connector, multi_anchor::MultiAnchor};
use strata_bridge_exec::{
    cpfp::{
        adapters::{BitcoindCpfpMempool, OperatorWalletCpfpAdapter},
        ladder::{self, CpfpContext, CpfpHandle, CpfpMempool, InputSigner, ParentProbe},
        submitpackage::{SubmitPackageError, SubmitPackageSummary},
    },
    fees,
};
use strata_bridge_primitives::cpfp::ChildSpend;
use tokio::sync::RwLock;

/// Test fee target: well above what the parent pays, so the bump path fires.
const TEST_FEE_TARGET: u64 = 20;
/// Cap (`max_fee_rate`) for the package; well above the target.
const TEST_FEE_CAP: u64 = 100;
/// Fee rate used to fund the v3 parent. Independent of the package target — just needs to be
/// above min-relay so the parent on its own is mempool-valid.
const PARENT_FEE_RATE_SAT_PER_VB: u64 = 5;

/// `Fixed` fee source that always returns the same rate. Avoids depending on bitcoind's
/// estimatesmartfee (which returns 0 in a quiet regtest).
#[derive(Debug)]
struct FixedFeeSource(FeeRate);

#[async_trait]
impl fees::FeeSource for FixedFeeSource {
    async fn next_block_rate(&self) -> Result<FeeRate, fees::FeeSourceError> {
        Ok(self.0)
    }
}

/// Boots `bitcoind`, mines coinbase maturity, and returns the node plus an async RPC client.
fn setup_bitcoind() -> (corepc_node::Node, BitcoinClient) {
    // Child adoption reads confirmed funding through the `txindex` of the node.
    let mut conf = corepc_node::Conf::default();
    conf.args.push("-txindex=1");
    let bitcoind = corepc_node::Node::with_conf("bitcoind", &conf).expect("bitcoind must start");
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

/// Constructs an `OperatorWallet` whose general funds are keyed to `pubkey`, over in-memory
/// stores, and syncs it against `bitcoind`. Sends `funding_utxos` separate UTXOs of
/// `funding_per_utxo` each to the wallet's address so subsequent fundings (parent + child) draw
/// from distinct UTXOs without needing intra-test rescans.
async fn build_operator_wallet(
    bitcoind: &corepc_node::Node,
    pubkey: XOnlyPublicKey,
    funding_utxos: usize,
    funding_per_utxo: Amount,
) -> Arc<RwLock<OperatorWallet<MemoryStore>>> {
    let backend = Backend::BitcoinCore(Arc::new(sync_rpc_client(bitcoind)));
    let config = OperatorWalletConfig::new(Amount::from_sat(330), 0, Network::Regtest);
    let secp = Secp256k1::new();
    let reserved_secret = SecretKey::from_slice(&[0x42u8; 32]).expect("valid 32-byte scalar");
    let reserved_keypair = Keypair::from_secret_key(&secp, &reserved_secret);
    let (reserved_pubkey, _) = reserved_keypair.x_only_public_key();
    let mut wallet = OperatorWallet::load_or_create(
        GeneralCustody::SecretService {
            general_key: pubkey,
            store: MemoryStore::new(),
        },
        reserved_pubkey,
        config,
        backend,
        MemoryStore::new(),
        None,
        BTreeSet::new(),
    )
    .await
    .expect("operator wallet init");

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

/// A v3 parent with `outputs`, funded from the general wallet at `parent_fee_rate` and signed
/// with `operator_keypair`.
async fn build_v3_parent(
    wallet: &Arc<RwLock<OperatorWallet<MemoryStore>>>,
    operator_keypair: Keypair,
    outputs: Vec<TxOut>,
    parent_fee_rate: FeeRate,
) -> Transaction {
    let funded = {
        let mut wallet = wallet.write().await;
        wallet
            .fund_v3_transaction(
                outputs,
                parent_fee_rate,
                GeneralUtxoPolicy::ConfirmedOnly,
                operator_wallet::LeaseOwner::ClaimFundingRefill,
            )
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

/// The keyed anchor output of a parent.
fn anchor_output(operator_pubkey: XOnlyPublicKey) -> TxOut {
    TxOut {
        value: Amount::from_sat(330),
        script_pubkey: Address::p2tr(&Secp256k1::new(), operator_pubkey, None, Network::Regtest)
            .script_pubkey(),
    }
}

/// Signs every PSBT input whose outpoint is NOT in `skip` as Taproot key-path with
/// `keypair` (BIP-341 tap-tweak with no merkle root), placing the resulting Schnorr signature
/// in `tap_key_sig`. Requires `witness_utxo` to be set on every input.
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
    let parent = build_v3_parent(
        &wallet,
        operator_keypair,
        vec![anchor_output(operator_pubkey)],
        parent_fee_rate,
    )
    .await;
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
    let cpfp_wallet = Arc::new(OperatorWalletCpfpAdapter::new(wallet.clone()));
    let cpfp_mempool = Arc::new(BitcoindCpfpMempool::new(async_client.clone()));
    let fee_source = Arc::new(FixedFeeSource(
        FeeRate::from_sat_per_vb(TEST_FEE_TARGET).unwrap(),
    ));
    let max_fee_rate = FeeRate::from_sat_per_vb(TEST_FEE_CAP).unwrap();

    let anchor_input_signer = test_input_signer(operator_keypair);
    let wallet_input_signer = test_input_signer(operator_keypair);

    let ctx = CpfpContext {
        wallet: cpfp_wallet,
        multi_anchor_signer: test_input_signer(operator_keypair),
        fee_source,
        anchor_input_signer,
        wallet_input_signer,
        // Neutral fee settings: the e2e tests pin the raw-estimate-to-cap behavior.
        policy: fees::FeeTargetPolicy {
            premium_percent: 0,
            min_package_fee_rate: FeeRate::ZERO,
            max_fee_rate,
        },
        mempool: cpfp_mempool,
    };

    // ── 4. perform_bump → submits [parent, child] package ──────────────────
    let strategy = CpfpStrategy {
        spend: ChildSpend::keyed_anchor(OutPoint {
            txid: parent.compute_txid(),
            vout: anchor_vout,
        }),
        parent_fee,
        deadline: DeadlineClass::NoDeadline,
        first_bump: FirstBump::AtPublish,
    };
    let mut handle = CpfpHandle::default();
    let unbroadcast = BitcoindCpfpMempool::new(async_client.clone())
        .probe(parent_txid)
        .await
        .expect("probe must answer");
    assert!(
        matches!(unbroadcast, ParentProbe::Absent),
        "an unbroadcast parent reads as absent: {unbroadcast:?}"
    );
    let bumped = ladder::perform_bump(&ctx, &parent, &strategy, &mut handle)
        .await
        .outcome()
        .expect("perform_bump must succeed end-to-end");
    assert_eq!(
        bumped,
        BumpOutcome::Submitted,
        "expected the bump to fire (target {TEST_FEE_TARGET} sat/vB > what the parent pays)"
    );

    // ── 5. Assert: mempool contains parent + child ─────────────────────────
    let child_txid = handle.accepted_txid().expect("child recorded");
    let _ = async_client
        .get_raw_transaction_verbosity_one(&parent_txid)
        .await
        .expect("parent must be in mempool or chain");
    let _ = async_client
        .get_raw_transaction_verbosity_one(&child_txid)
        .await
        .expect("child must be in mempool");

    assert_package_pays_target(&bitcoind, child_txid);

    // The probe reads the child that the ladder built, and its inputs resolve against the node.
    let mempool = BitcoindCpfpMempool::new(async_client.clone());
    let probe = mempool.probe(parent_txid).await.expect("probe must answer");
    let ParentProbe::Child(child) = probe else {
        panic!("the probe must report the child: {probe:?}");
    };
    assert_eq!(child.txid, child_txid);
    let mut lookup = mempool.child_inputs(child_txid).await;
    // The `txindex` of a fresh node can lag the block that confirmed the funding.
    for _ in 0..100 {
        if lookup.is_ok() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        lookup = mempool.child_inputs(child_txid).await;
    }
    let inputs = lookup.expect("the inputs must resolve");
    assert!(
        inputs
            .iter()
            .any(|input| input.outpoint.txid == parent_txid),
        "the child spends an output of the parent: {inputs:?}"
    );
    assert!(
        mempool.min_fee_rate().await.expect("minimum must answer") > FeeRate::ZERO,
        "a node always reports a minimum"
    );

    // ── 6. Mine a block and assert both confirm in it ──────────────────────
    //
    // Read the new block directly and assert both txids are in its txdata.
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

    // A confirmed parent reads as absent, and a parent alone in the mempool has no child.
    let confirmed = mempool.probe(parent_txid).await.expect("probe must answer");
    assert!(
        matches!(confirmed, ParentProbe::Absent),
        "a confirmed parent reads as absent: {confirmed:?}"
    );
    wallet.write().await.sync().await.expect("wallet sync");
    let lone = build_v3_parent(
        &wallet,
        operator_keypair,
        vec![anchor_output(operator_pubkey)],
        FeeRate::from_sat_per_vb(TEST_FEE_TARGET).unwrap(),
    )
    .await;
    async_client
        .send_raw_transaction(&lone, None)
        .await
        .expect("a parent at the target relays alone");
    let alone = mempool
        .probe(lone.compute_txid())
        .await
        .expect("probe must answer");
    assert!(
        matches!(alone, ParentProbe::NoChild),
        "a parent alone in the mempool has no child: {alone:?}"
    );
}

/// E2E test for an owned [`ChildSpend`]: a v3 parent whose only output is an
/// operator-owned payout, plus a CPFP child that spends that output
/// + a wallet funding input, drained back to the wallet. Pins that a child of an owned output on
/// a parent that is not yet broadcast confirms with the parent against real `bitcoind`.
#[tokio::test]
#[serial]
async fn cpfp_e2e_owned_output_against_bitcoind() {
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
    let payout_script = wallet
        .read()
        .await
        .descriptor()
        .expect("descriptor")
        .to_script();
    let parent = build_v3_parent(
        &wallet,
        operator_keypair,
        vec![TxOut {
            value: Amount::from_btc(0.25).unwrap(),
            script_pubkey: payout_script,
        }],
        parent_fee_rate,
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

    // CpfpContext, mirroring production wiring.
    let cpfp_wallet = Arc::new(OperatorWalletCpfpAdapter::new(wallet.clone()));
    let cpfp_mempool = Arc::new(BitcoindCpfpMempool::new(async_client.clone()));
    let fee_source = Arc::new(FixedFeeSource(
        FeeRate::from_sat_per_vb(TEST_FEE_TARGET).unwrap(),
    ));
    let max_fee_rate = FeeRate::from_sat_per_vb(TEST_FEE_CAP).unwrap();

    let anchor_input_signer = test_input_signer(operator_keypair);
    let wallet_input_signer = test_input_signer(operator_keypair);

    let ctx = CpfpContext {
        wallet: cpfp_wallet,
        multi_anchor_signer: test_input_signer(operator_keypair),
        fee_source,
        anchor_input_signer,
        wallet_input_signer,
        // Neutral fee settings: the e2e tests pin the raw-estimate-to-cap behavior.
        policy: fees::FeeTargetPolicy {
            premium_percent: 0,
            min_package_fee_rate: FeeRate::ZERO,
            max_fee_rate,
        },
        mempool: cpfp_mempool,
    };

    let strategy = CpfpStrategy {
        spend: ChildSpend::owned_output(payout_outpoint),
        parent_fee,
        deadline: DeadlineClass::NoDeadline,
        first_bump: FirstBump::AtPublish,
    };
    let mut handle = CpfpHandle::default();
    let bumped = ladder::perform_bump(&ctx, &parent, &strategy, &mut handle)
        .await
        .outcome()
        .expect("perform_bump must succeed end-to-end for an owned spend");
    assert_eq!(
        bumped,
        BumpOutcome::Submitted,
        "expected the bump to fire (target {TEST_FEE_TARGET} sat/vB > what the parent pays)"
    );

    let child_txid = handle.accepted_txid().expect("child recorded");
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
        "owned-output child must confirm in the same block as the parent"
    );
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

/// E2E test for the multi-anchor script-path CPFP pipeline against real `bitcoind`.
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
    let parent = build_v3_parent(
        &wallet,
        operator_keypair,
        vec![anchor.tx_out()],
        parent_fee_rate,
    )
    .await;
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
    // The key-path anchor signer is wired to fail: a multi-anchor bump must never
    // consult it, so any routing regression surfaces as a hard test failure here too.
    let anchor_input_signer: InputSigner = Arc::new(move |_msg: Message| {
        Box::pin(async move {
            Err(ladder::SignerError(
                "anchor_input_signer must not be called for a multi-anchor bump".into(),
            ))
        })
    });
    let ctx = CpfpContext {
        wallet: Arc::new(OperatorWalletCpfpAdapter::new(wallet.clone())),
        multi_anchor_signer: test_untweaked_input_signer(our_wt_keypair),
        fee_source: Arc::new(FixedFeeSource(
            FeeRate::from_sat_per_vb(TEST_FEE_TARGET).unwrap(),
        )),
        anchor_input_signer,
        wallet_input_signer: test_input_signer(operator_keypair),
        // Neutral fee settings: the e2e tests pin the raw-estimate-to-cap behavior.
        policy: fees::FeeTargetPolicy {
            premium_percent: 0,
            min_package_fee_rate: FeeRate::ZERO,
            max_fee_rate: FeeRate::from_sat_per_vb(TEST_FEE_CAP).unwrap(),
        },
        mempool: Arc::new(BitcoindCpfpMempool::new(async_client.clone())),
    };

    // ── 5. perform_bump → [parent, child] package via the script path ──────
    let strategy = CpfpStrategy {
        spend: ChildSpend::multi_anchor(
            OutPoint {
                txid: parent.compute_txid(),
                vout: anchor_vout,
            },
            leaf_script,
            control_block,
        ),
        parent_fee,
        deadline: DeadlineClass::NoDeadline,
        first_bump: FirstBump::AtPublish,
    };
    let mut handle = CpfpHandle::default();
    let bumped = ladder::perform_bump(&ctx, &parent, &strategy, &mut handle)
        .await
        .outcome()
        .expect("perform_bump must succeed end-to-end for a multi-anchor spend");
    assert_eq!(
        bumped,
        BumpOutcome::Submitted,
        "bump must fire at a target above what the parent pays"
    );

    // ── 6. Mempool + package feerate + confirmation ────────────────────────
    let child_txid = handle.accepted_txid().expect("child recorded");
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
/// string is what `SubmitPackageError::replacement_rejection` matches, and matching on a
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
    let parent = build_v3_parent(
        &wallet,
        operator_keypair,
        vec![anchor.tx_out()],
        parent_fee_rate,
    )
    .await;
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
            wallet: Arc::new(OperatorWalletCpfpAdapter::new(wallet.clone())),
            multi_anchor_signer: test_untweaked_input_signer(wt_keypairs[slot]),
            fee_source: Arc::new(FixedFeeSource(
                FeeRate::from_sat_per_vb(TEST_FEE_TARGET).unwrap(),
            )),
            anchor_input_signer: test_input_signer(operator_keypair),
            wallet_input_signer: test_input_signer(operator_keypair),
            // Neutral fee settings: the e2e tests pin the raw-estimate-to-cap behavior.
            policy: fees::FeeTargetPolicy {
                premium_percent: 0,
                min_package_fee_rate: FeeRate::ZERO,
                max_fee_rate: FeeRate::from_sat_per_vb(TEST_FEE_CAP).unwrap(),
            },
            mempool: Arc::new(BitcoindCpfpMempool::new(async_client.clone())),
        };
        let strategy = CpfpStrategy {
            spend: ChildSpend::multi_anchor(
                OutPoint {
                    txid: parent.compute_txid(),
                    vout: anchor_vout,
                },
                leaf_script,
                control_block,
            ),
            parent_fee,
            deadline: DeadlineClass::NoDeadline,
            first_bump: FirstBump::AtPublish,
        };
        (ctx, strategy)
    };

    // Watchtower 0 takes the anchor.
    let (ctx0, strategy0) = context_for(0);
    let mut handle0 = CpfpHandle::default();
    let bumped = ladder::perform_bump(&ctx0, &parent, &strategy0, &mut handle0)
        .await
        .outcome()
        .expect("the first watchtower must win the anchor");
    assert_eq!(
        bumped,
        BumpOutcome::Submitted,
        "the first bump must submit a package"
    );

    // Watchtower 1 now sees the anchor taken at target, and skips.
    let (ctx1, strategy1) = context_for(1);
    let mut handle1 = CpfpHandle::default();
    let bumped = ladder::perform_bump(&ctx1, &parent, &strategy1, &mut handle1)
        .await
        .outcome()
        .expect("a lost anchor is not an error");
    assert_eq!(
        bumped,
        BumpOutcome::ParentIsLive,
        "the second watchtower must stand down, and it must report that the first \
         watchtower's child already carries the parent"
    );
    // Both watchtowers share one wallet in this test, so the second can adopt the first's child.
    // It must not build one of its own.
    assert!(
        handle1
            .accepted_txid()
            .is_none_or(|txid| Some(txid) == handle0.accepted_txid()),
        "a skipping watchtower must not build or sign a child"
    );

    // Pin the rejection that the skip avoids.
    //
    // The skip works, so no watchtower reaches the submission any more. Reproduce what one
    // without the check meets by reporting the anchor as unspent while leaving the submission
    // real. This is the only way to hold the bitcoind message that
    // `replacement_rejection` matches against a live node.
    let (ctx2, strategy2) = context_for(2);
    let ctx2 = CpfpContext {
        mempool: Arc::new(BlindToSpends(BitcoindCpfpMempool::new(
            async_client.clone(),
        ))),
        ..ctx2
    };
    let mut handle2 = CpfpHandle::default();
    let forced = ladder::perform_bump(&ctx2, &parent, &strategy2, &mut handle2)
        .await
        .outcome();

    let err = forced.expect_err("a same-target child cannot displace the winner");
    assert!(
        err.replacement_rejection().is_some(),
        "a lost race must classify as contention, not as a fault: {err}"
    );
}

/// Wraps the real mempool adapter and reports every parent as childless.
///
/// Submission stays real. Only the pre-build check is blinded, so a bump proceeds to the point
/// where bitcoind itself rejects it.
#[derive(Debug)]
struct BlindToSpends(BitcoindCpfpMempool);

#[async_trait]
impl CpfpMempool for BlindToSpends {
    async fn submit_package(
        &self,
        txs: &[Transaction],
    ) -> Result<SubmitPackageSummary, SubmitPackageError> {
        self.0.submit_package(txs).await
    }

    async fn probe(&self, _parent: Txid) -> Result<ParentProbe, ladder::MempoolError> {
        Ok(ParentProbe::NoChild)
    }

    async fn child_inputs(
        &self,
        child: Txid,
    ) -> Result<Vec<operator_wallet::FundingInput>, ladder::MempoolError> {
        self.0.child_inputs(child).await
    }

    async fn min_fee_rate(&self) -> Result<FeeRate, ladder::MempoolError> {
        self.0.min_fee_rate().await
    }
}
