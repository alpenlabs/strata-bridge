//! Tests of one CPFP bump attempt, against a fake wallet, mempool and signers.

use std::{num::NonZeroU64, sync::Arc};

use bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, Transaction, TxIn, TxOut, Txid, Witness,
    XOnlyPublicKey, absolute,
    hashes::Hash,
    opcodes, script,
    secp256k1::{Message, SECP256K1, schnorr::Signature},
    taproot::{LeafVersion, TaprootBuilder},
    transaction::Version,
};
use btc_tracker::cpfp::{BumpOutcome, CpfpBumper, CpfpStrategy, DeadlineClass, FirstBump};
use operator_wallet::IncumbentChild;
use strata_bridge_primitives::cpfp::ChildSpend;

use super::{errors::*, handle::*, interfaces::*, ladder::*, test_utils::*};
use crate::fees::FeeTargetPolicy;

fn anchor_strategy(parent: &Transaction) -> CpfpStrategy {
    CpfpStrategy {
        spend: ChildSpend::keyed_anchor(OutPoint::new(parent.compute_txid(), 0)),
        parent_fee: Amount::from_sat(220),
        deadline: DeadlineClass::NoDeadline,
        first_bump: FirstBump::AtPublish,
    }
}

/// A minimal one-leaf multi-anchor strategy. The contention tests use this shape to cover the
/// shared-anchor path.
/// The leaf and control block stay structurally valid even though the skip paths never
/// spend the anchor.
fn multi_anchor_strategy(parent: &Transaction, anchor_key: XOnlyPublicKey) -> CpfpStrategy {
    let leaf = script::Builder::new()
        .push_slice(anchor_key.serialize())
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script();
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, leaf.clone())
        .expect("depth 0 leaf is always valid")
        .finalize(SECP256K1, anchor_key)
        .expect("single-leaf tree finalizes");
    let control_block = spend_info
        .control_block(&(leaf.clone(), LeafVersion::TapScript))
        .expect("control block for the only leaf");
    CpfpStrategy {
        spend: ChildSpend::multi_anchor(
            OutPoint::new(parent.compute_txid(), 0),
            leaf,
            control_block,
        ),
        parent_fee: Amount::from_sat(220),
        deadline: DeadlineClass::NoDeadline,
        first_bump: FirstBump::AtPublish,
    }
}

/// The incumbent that the wallet must see for a [`child_at`] probe.
fn incumbent_of_child_at() -> IncumbentChild {
    IncumbentChild {
        fee: Amount::from_sat(500),
        vbytes: NonZeroU64::new(200).unwrap(),
    }
}

/// The outpoints that the leases of the handle hold, or an empty vector when it holds none.
fn held_by(handle: &CpfpHandle) -> Vec<OutPoint> {
    [&handle.accepted, &handle.candidate]
        .into_iter()
        .flatten()
        .flat_map(|child| child.lease.inputs().iter().map(|i| i.outpoint))
        .collect()
}

fn contention_context(wallet: Arc<FakeWallet>, mempool: Arc<FakeMempool>) -> CpfpContext {
    context(
        Arc::new(FakeFeeSource::returning(
            FeeRate::from_sat_per_vb(8).unwrap(),
        )),
        wallet,
        mempool,
        fake_input_signer_ok(),
        fake_input_signer_ok(),
        FeeRate::from_sat_per_vb(20).unwrap(),
    )
}

/// A competitor's child covers the shared anchor at (or above) our target: we stand
/// down, and standing down must hand the last child's funding leases back — the next
/// build for this parent may never come, and nothing else records those outpoints.
#[tokio::test]
async fn losing_a_shared_anchor_releases_the_last_childs_funding() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let ours = Txid::from_byte_array([0xAA; 32]);
    let theirs = Txid::from_byte_array([0xBB; 32]);
    let inputs = [
        OutPoint::new(Txid::from_byte_array([1; 32]), 0),
        OutPoint::new(Txid::from_byte_array([2; 32]), 1),
    ];
    let wallet = Arc::new(FakeWallet::failing("skip must not build"));
    let mempool = Arc::new(
        FakeMempool::failing("skip must not submit")
            .with_probe(child_at(theirs, FeeRate::from_sat_per_vb_unchecked(10))),
    );
    let ctx = contention_context(wallet.clone(), mempool);
    let mut handle = seeded_handle(&wallet, &inputs, ours);
    let bumped = run_bump(
        &ctx,
        &parent,
        &multi_anchor_strategy(&parent, anchor_key),
        &mut handle,
    )
    .await
    .expect("losing the anchor is a skip, not an error");
    assert_eq!(
        bumped,
        BumpOutcome::ParentIsLive,
        "a child that spends the anchor proves the parent reached the network"
    );
    assert_eq!(*wallet.released.lock().unwrap(), inputs.to_vec());
    assert!(handle.accepted.is_none() && handle.candidate.is_none());
}

/// Our own child holds the anchor at the target. This is the normal state. The leases
/// must stay: a release lets a concurrent build double-spend the live child's funding
/// and evict our own child.
#[tokio::test]
async fn our_own_winning_child_keeps_its_funding_leases() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let ours = Txid::from_byte_array([0xAA; 32]);
    let inputs = [OutPoint::new(Txid::from_byte_array([1; 32]), 0)];
    let wallet = Arc::new(FakeWallet::failing("skip must not build"));
    let mempool = Arc::new(
        FakeMempool::failing("skip must not submit")
            .with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(10))),
    );
    let ctx = contention_context(wallet.clone(), mempool);
    let mut handle = seeded_handle(&wallet, &inputs, ours);
    let bumped = run_bump(
        &ctx,
        &parent,
        &multi_anchor_strategy(&parent, anchor_key),
        &mut handle,
    )
    .await
    .expect("holding the anchor is a skip, not an error");
    assert_eq!(
        bumped,
        BumpOutcome::ParentIsLive,
        "a child that spends the anchor proves the parent reached the network"
    );
    assert!(wallet.released.lock().unwrap().is_empty());
    assert_eq!(held_by(&handle), inputs.to_vec());
}

/// A failed probe does not stop a first child: the submission is the authority.
#[tokio::test]
async fn a_failed_probe_builds_when_the_handle_records_no_child() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let wallet = Arc::new(FakeWallet::returning(
        synthetic_child_psbt(&parent, 0),
        vec![OutPoint {
            txid: parent.compute_txid(),
            vout: 7,
        }],
    ));
    let mempool = Arc::new(FakeMempool::ok().with_failing_probe("probe RPC failure"));
    let ctx = contention_context(wallet.clone(), mempool.clone());
    let mut handle = CpfpHandle::default();
    let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .expect("a probe failure must not fail the bump");
    assert_eq!(bumped, BumpOutcome::Submitted);
    assert_eq!(
        mempool.captured.lock().unwrap().len(),
        1,
        "the build must reach the submission despite the probe error"
    );
}

#[tokio::test]
async fn happy_path_submits_package_and_updates_handle() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let psbt = synthetic_child_psbt(&parent, 0);
    let wallet_funding = vec![OutPoint {
        txid: bitcoin::Txid::from_slice(&[1u8; 32]).unwrap(),
        vout: 0,
    }];

    let mempool = Arc::new(FakeMempool::ok());
    let wallet = Arc::new(FakeWallet::returning(psbt, wallet_funding.clone()));
    let ctx = context(
        Arc::new(FakeFeeSource::returning(
            FeeRate::from_sat_per_vb(10).unwrap(),
        )),
        wallet.clone(),
        mempool.clone(),
        fake_input_signer_ok(),
        fake_input_signer_ok(),
        FeeRate::from_sat_per_vb(50).unwrap(),
    );

    let mut handle = CpfpHandle::default();
    let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .expect("happy path must submit");
    assert_eq!(bumped, BumpOutcome::Submitted);

    // handle is updated
    assert_eq!(wallet.target(), Some(FeeRate::from_sat_per_vb(10).unwrap()));
    assert_eq!(held_by(&handle), wallet_funding);
    assert!(handle.accepted.is_some());

    // mempool received [parent, child]
    let captured = mempool.captured.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].len(), 2);
    assert_eq!(captured[0][0].compute_txid(), parent.compute_txid());
}

/// A rejected candidate is not the incumbent, and the node did not relay it: the handle
/// records nothing and the inputs go back to the wallet.
#[tokio::test]
async fn a_rejected_candidate_is_not_recorded() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let psbt = synthetic_child_psbt(&parent, 0);
    let wallet_funding = vec![OutPoint {
        txid: bitcoin::Txid::from_slice(&[1u8; 32]).unwrap(),
        vout: 0,
    }];

    let mempool = Arc::new(FakeMempool::failing("min relay fee not met"));
    let wallet = Arc::new(FakeWallet::returning(psbt, wallet_funding.clone()));
    let ctx = context(
        Arc::new(FakeFeeSource::returning(
            FeeRate::from_sat_per_vb(10).unwrap(),
        )),
        wallet.clone(),
        mempool.clone(),
        fake_input_signer_ok(),
        fake_input_signer_ok(),
        FeeRate::from_sat_per_vb(50).unwrap(),
    );

    let mut handle = CpfpHandle::default();
    run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .expect_err("a failing mempool must surface the error");

    assert!(handle.accepted.is_none() && handle.candidate.is_none());
    assert_eq!(*wallet.released.lock().unwrap(), wallet_funding);
}

/// The mempool read needs no price. A fee outage still adopts a live child of ours, and the
/// fresh read still reports the parent.
#[tokio::test]
async fn a_fee_source_failure_still_adopts_a_live_child() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let ours = Txid::from_byte_array([0xAA; 32]);
    let ctx = context(
        Arc::new(FakeFeeSource::failing()),
        Arc::new(FakeWallet {
            owns_children: true,
            ..FakeWallet::failing("no build")
        }),
        Arc::new(FakeMempool::ok().with_probe(child_at(ours, FeeRate::ZERO))),
        fake_input_signer_ok(),
        fake_input_signer_ok(),
        FeeRate::from_sat_per_vb(20).unwrap(),
    );
    let mut state = CpfpHandle::default();

    let outcome = ctx
        .bump(&parent, &anchor_strategy(&parent), &mut state)
        .await;

    assert_eq!(outcome, BumpOutcome::ParentIsLive);
    let handle = &state;
    assert_eq!(handle.accepted_txid(), Some(ours));
}

/// An attempt that read no parent reports no parent, whatever an earlier attempt read.
#[tokio::test]
async fn a_fee_source_failure_after_an_eviction_does_not_report_a_live_parent() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let mempool = Arc::new(FakeMempool::ok().with_probe(ParentProbe::NoChild));
    let ctx = context(
        Arc::new(FakeFeeSource::failing()),
        Arc::new(FakeWallet::failing("no build")),
        mempool.clone(),
        fake_input_signer_ok(),
        fake_input_signer_ok(),
        FeeRate::from_sat_per_vb(20).unwrap(),
    );
    let mut state = CpfpHandle::default();
    let strategy = anchor_strategy(&parent);

    assert_eq!(
        ctx.bump(&parent, &strategy, &mut state).await,
        BumpOutcome::ParentIsLive
    );
    mempool.report(ParentProbe::Absent);
    assert_eq!(
        ctx.bump(&parent, &strategy, &mut state).await,
        BumpOutcome::NoPackage
    );
}

#[tokio::test]
async fn fee_source_failure_surfaces() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let ctx = context(
        Arc::new(FakeFeeSource::failing()),
        Arc::new(FakeWallet::failing("wallet must not be called")),
        Arc::new(FakeMempool::failing("mempool must not be called")),
        fake_input_signer_ok(),
        fake_input_signer_ok(),
        FeeRate::from_sat_per_vb(20).unwrap(),
    );
    let mut handle = CpfpHandle::default();
    let err = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .unwrap_err();
    assert!(matches!(err, CpfpError::FeeSource(_)));
    assert!(handle.accepted.is_none());
}

#[tokio::test]
async fn anchor_signer_failure_surfaces() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let psbt = synthetic_child_psbt(&parent, 0);

    let ctx = context(
        Arc::new(FakeFeeSource::returning(
            FeeRate::from_sat_per_vb(10).unwrap(),
        )),
        Arc::new(FakeWallet::returning(psbt, Vec::new())),
        Arc::new(FakeMempool::failing("must not be called when signer fails")),
        fake_input_signer_failing("anchor sign boom"),
        fake_input_signer_ok(),
        FeeRate::from_sat_per_vb(20).unwrap(),
    );
    let mut handle = CpfpHandle::default();
    let err = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .unwrap_err();
    assert!(matches!(err, CpfpError::AnchorSigner(_)));
    assert!(handle.accepted.is_none());
}

/// A funding failure can hide a top-up, so the next attempt must read a fresh view.
#[tokio::test]
async fn a_funding_failure_refreshes_the_wallet() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let wallet = Arc::new(FakeWallet::failing("insufficient funds"));
    let ctx = context(
        Arc::new(FakeFeeSource::returning(
            FeeRate::from_sat_per_vb(10).unwrap(),
        )),
        wallet.clone(),
        Arc::new(FakeMempool::failing("must not be called")),
        fake_input_signer_ok(),
        fake_input_signer_ok(),
        FeeRate::from_sat_per_vb(20).unwrap(),
    );
    let mut handle = CpfpHandle::default();
    perform_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .outcome()
        .unwrap_err();
    assert_eq!(*wallet.refreshes.lock().unwrap(), 1);
}

/// A parent that cannot carry a child does not depend on the view of the wallet.
#[tokio::test]
async fn an_unbumpable_parent_does_not_refresh_the_wallet() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let wallet = Arc::new(FakeWallet::unbumpable("no such output"));
    let ctx = context(
        Arc::new(FakeFeeSource::returning(
            FeeRate::from_sat_per_vb(10).unwrap(),
        )),
        wallet.clone(),
        Arc::new(FakeMempool::failing("must not be called")),
        fake_input_signer_ok(),
        fake_input_signer_ok(),
        FeeRate::from_sat_per_vb(20).unwrap(),
    );
    let mut handle = CpfpHandle::default();
    perform_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .outcome()
        .unwrap_err();
    assert_eq!(*wallet.refreshes.lock().unwrap(), 0);
}

/// The child spends an input that the chain already spent. The handle must forget the child,
/// or the next build re-admits that input, and the view must catch up with the chain.
#[tokio::test]
async fn a_missing_input_clears_the_handle_and_refreshes_the_wallet() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let psbt = synthetic_child_psbt(&parent, 0);
    let stale = OutPoint::new(Txid::from_byte_array([8; 32]), 0);
    let wallet = Arc::new(FakeWallet::returning(psbt, vec![stale]));
    let ctx = context(
        Arc::new(FakeFeeSource::returning(
            FeeRate::from_sat_per_vb(10).unwrap(),
        )),
        wallet.clone(),
        Arc::new(FakeMempool::failing(
            "package-not-child-with-unconfirmed-parents",
        )),
        fake_input_signer_ok(),
        fake_input_signer_ok(),
        FeeRate::from_sat_per_vb(20).unwrap(),
    );
    let mut handle = seeded_handle(&wallet, &[stale], Txid::from_byte_array([7; 32]));
    perform_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .outcome()
        .unwrap_err();
    assert!(handle.accepted.is_none());
    assert!(handle.candidate.is_none());
    assert_eq!(*wallet.refreshes.lock().unwrap(), 1);
}

/// A witness that the signer returns is final. The ladder must not sign that input
/// again: its own signer holds another key.
#[tokio::test]
async fn a_signer_witness_is_used_verbatim() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let psbt = synthetic_child_psbt(&parent, 0);
    let sentinel = Signature::from_slice(&[0x42u8; 64]).expect("64 bytes");
    let mut sentinel_witness = Witness::new();
    sentinel_witness.push(sentinel.as_ref());

    let panicking_wallet_signer: InputSigner = Arc::new(|_msg: Message| {
        Box::pin(async move { panic!("the signer signed every wallet input") })
    });

    let wallet = FakeWallet {
        signer_witnesses: vec![(1, sentinel_witness.clone())],
        ..FakeWallet::returning(psbt, Vec::new())
    };
    let wallet = Arc::new(wallet);
    let mempool = Arc::new(FakeMempool::ok());
    let ctx = context(
        Arc::new(FakeFeeSource::returning(
            FeeRate::from_sat_per_vb(10).unwrap(),
        )),
        wallet.clone(),
        mempool.clone(),
        fake_input_signer_ok(),
        panicking_wallet_signer,
        FeeRate::from_sat_per_vb(50).unwrap(),
    );
    let mut handle = CpfpHandle::default();
    let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .expect("the bump must submit without the wallet input signer");
    assert_eq!(bumped, BumpOutcome::Submitted);

    assert_eq!(
        *wallet.sign_requests.lock().unwrap(),
        vec![vec![1]],
        "the anchor is not a wallet input"
    );
    let captured = mempool.captured.lock().unwrap();
    assert_eq!(captured[0][1].input[1].witness, sentinel_witness);
}

#[tokio::test]
async fn an_owned_spend_submits_without_the_anchor_signer() {
    // An owned spend has no foreign-key input. The bump must:
    // (a) build the child via the wallet,
    // (b) NOT invoke the anchor signer,
    // (c) submit the package as usual.
    //
    // We assert (b) by supplying an anchor signer that panics if called — the test would
    // panic instead of pass if the bump incorrectly entered the anchor path.
    let wallet_script = Address::p2tr(
        SECP256K1,
        test_keypair_and_xonly().1,
        None,
        Network::Regtest,
    )
    .script_pubkey();
    let payout_outpoint = OutPoint {
        txid: bitcoin::Txid::from_slice(&[42u8; 32]).unwrap(),
        vout: 1,
    };
    // The "parent" is a dummy v3 tx — its content doesn't matter for an owned spend,
    // since the wallet builds the child against the payout outpoint directly.
    let parent = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: wallet_script.clone(),
        }],
    };
    let psbt = owned_output_child_psbt(payout_outpoint, wallet_script);

    let panicking_anchor_signer: InputSigner = Arc::new(|_msg: Message| {
        Box::pin(async move {
            panic!("anchor signer must NOT be called for an owned spend");
        })
    });

    let mempool = Arc::new(FakeMempool::ok());
    let wallet = Arc::new(FakeWallet::returning(psbt, vec![payout_outpoint]));
    let ctx = context(
        Arc::new(FakeFeeSource::returning(
            FeeRate::from_sat_per_vb(10).unwrap(),
        )),
        wallet.clone(),
        mempool.clone(),
        panicking_anchor_signer,
        fake_input_signer_ok(),
        FeeRate::from_sat_per_vb(50).unwrap(),
    );

    let mut handle = CpfpHandle::default();
    let strategy = CpfpStrategy {
        spend: ChildSpend::owned_output(payout_outpoint),
        parent_fee: Amount::from_sat(300),
        deadline: DeadlineClass::NoDeadline,
        first_bump: FirstBump::AtPublish,
    };
    let bumped = run_bump(&ctx, &parent, &strategy, &mut handle)
        .await
        .expect("an owned spend must submit");
    assert_eq!(bumped, BumpOutcome::Submitted);

    assert_eq!(wallet.target(), Some(FeeRate::from_sat_per_vb(10).unwrap()));
    assert!(handle.accepted.is_some());

    // mempool received [parent, child]
    let captured = mempool.captured.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].len(), 2);
    assert_eq!(captured[0][0].compute_txid(), parent.compute_txid());
}

/// A rejection means that the node did not take the child and did not relay it. The new
/// lease drops, and the lease of the live child stays, even with no input in common.
#[tokio::test]
async fn a_rejected_replacement_keeps_the_lease_of_the_live_child() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let outpoint = |vout| OutPoint::new(parent.compute_txid(), vout);
    let ours = Txid::from_byte_array([0xAA; 32]);
    let wallet = Arc::new(FakeWallet::returning(
        synthetic_child_psbt(&parent, 0),
        vec![outpoint(7)],
    ));
    let mut handle = seeded_handle(&wallet, &[outpoint(8)], ours);
    let ctx = context(
        Arc::new(FakeFeeSource::returning(
            FeeRate::from_sat_per_vb(10).unwrap(),
        )),
        wallet.clone(),
        Arc::new(
            FakeMempool::failing("package-not-valid")
                .with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(5))),
        ),
        fake_input_signer_ok(),
        fake_input_signer_ok(),
        FeeRate::from_sat_per_vb(20).unwrap(),
    );
    run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .unwrap_err();

    assert_eq!(*wallet.released.lock().unwrap(), vec![outpoint(7)]);
    assert_eq!(held_by(&handle), vec![outpoint(8)]);
    assert_eq!(handle.accepted_txid(), Some(ours));
}

/// An RPC failure does not prove that the package stayed off the network. The candidate
/// keeps its lease, and a later probe that reports the child promotes it. The child is ours,
/// so its funding stays held and no lookup runs.
#[tokio::test]
async fn a_submission_with_an_unknown_result_keeps_the_child_of_a_later_probe() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let funding = vec![OutPoint::new(parent.compute_txid(), 7)];
    let wallet = Arc::new(FakeWallet::returning(
        synthetic_child_psbt(&parent, 0),
        funding.clone(),
    ));
    let mempool = Arc::new(FakeMempool::with_result(SubmitResult::Unknown));
    let ctx = contention_context(wallet.clone(), mempool.clone());
    let mut handle = CpfpHandle::default();
    run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .unwrap_err();
    let child_txid = handle.candidate.as_ref().expect("the lease stays").txid;
    assert!(handle.accepted.is_none());

    mempool.report(child_at(child_txid, FeeRate::from_sat_per_vb(8).unwrap()));
    let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .expect("the live child ends the attempt");

    assert_eq!(bumped, BumpOutcome::ParentIsLive);
    assert_eq!(handle.accepted_txid(), Some(child_txid));
    assert!(wallet.released.lock().unwrap().is_empty());
    assert_eq!(held_by(&handle), funding);
}

/// An unknown submission result leaves the live child and its lease in place.
#[tokio::test]
async fn a_failed_bump_stores_both_leases() {
    let (_, key) = test_keypair_and_xonly();
    let parent = synthetic_parent(key, Amount::from_sat(330));
    let outpoint = |vout| OutPoint::new(parent.compute_txid(), vout);
    let ours = Txid::from_byte_array([0xAA; 32]);
    let wallet = Arc::new(FakeWallet::returning(
        synthetic_child_psbt(&parent, 0),
        vec![outpoint(7)],
    ));
    let ctx = contention_context(
        wallet.clone(),
        Arc::new(
            FakeMempool::with_result(SubmitResult::Unknown)
                .with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(1))),
        ),
    );
    let mut state = seeded_handle(&wallet, &[outpoint(8)], ours);

    let outcome = ctx
        .bump(&parent, &anchor_strategy(&parent), &mut state)
        .await;

    assert_ne!(outcome, BumpOutcome::Submitted);
    let handle = &state;
    assert_eq!(held_by(handle), vec![outpoint(8), outpoint(7)]);
}

/// A failed signature means that nothing reached the network. The new lease drops, which
/// returns its inputs, and the lease of the prior child stays: that child is still live.
#[tokio::test]
async fn a_failed_signature_drops_the_new_lease_and_keeps_the_prior_one() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let outpoint = |vout| OutPoint {
        txid: parent.compute_txid(),
        vout,
    };
    let wallet = Arc::new(FakeWallet::returning(
        synthetic_child_psbt(&parent, 0),
        vec![outpoint(7)],
    ));
    let mut handle = seeded_handle(&wallet, &[outpoint(8)], Txid::all_zeros());
    let ctx = context(
        Arc::new(FakeFeeSource::returning(
            FeeRate::from_sat_per_vb(10).unwrap(),
        )),
        wallet.clone(),
        Arc::new(FakeMempool::ok().with_probe(child_at(
            Txid::all_zeros(),
            FeeRate::from_sat_per_vb_unchecked(5),
        ))),
        fake_input_signer_ok(),
        fake_input_signer_failing("signer offline"),
        FeeRate::from_sat_per_vb(20).unwrap(),
    );
    run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .unwrap_err();

    assert_eq!(*wallet.released.lock().unwrap(), vec![outpoint(7)]);
    assert_eq!(held_by(&handle), vec![outpoint(8)]);
}

/// A wallet signing failure is a retry, never a stop.
#[tokio::test]
async fn a_wallet_signing_failure_retries_on_the_next_trigger() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let wallet = FakeWallet {
        sign_error: Some(SignerError("vault offline".to_string())),
        ..FakeWallet::returning(synthetic_child_psbt(&parent, 0), Vec::new())
    };
    let mempool = Arc::new(FakeMempool::ok().with_probe(ParentProbe::Absent));
    let ctx = contention_context(Arc::new(wallet), mempool.clone());

    let outcome = ctx
        .bump(
            &parent,
            &anchor_strategy(&parent),
            &mut CpfpHandle::default(),
        )
        .await;

    assert_eq!(outcome, BumpOutcome::NoPackage);
    assert_eq!(mempool.submissions(), 0);
}

/// A child holds the fee of the whole package in its own few vbytes. No limit on its own rate
/// stops a package that the cap allows.
#[tokio::test]
async fn a_child_with_a_very_high_own_rate_reaches_the_node() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let mut psbt = synthetic_child_psbt(&parent, 0);
    psbt.inputs[1].witness_utxo.as_mut().unwrap().value = Amount::from_btc(1.0).unwrap();
    let mempool = Arc::new(FakeMempool::ok());
    let ctx = contention_context(
        Arc::new(FakeWallet::returning(psbt, Vec::new())),
        mempool.clone(),
    );

    let bumped = run_bump(
        &ctx,
        &parent,
        &anchor_strategy(&parent),
        &mut CpfpHandle::default(),
    )
    .await
    .expect("the package must submit");

    assert_eq!(bumped, BumpOutcome::Submitted);
    assert_eq!(mempool.submissions(), 1);
}

/// A signer that answers for fewer inputs than it was asked about must not reach the
/// network: a missing witness is a signer fault, and the next trigger retries.
#[tokio::test]
async fn a_signer_that_drops_a_signature_fails_as_a_signer_fault() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let wallet = FakeWallet {
        drops_a_signature: true,
        ..FakeWallet::returning(synthetic_child_psbt(&parent, 0), Vec::new())
    };
    let mempool = Arc::new(FakeMempool::ok());
    let ctx = contention_context(Arc::new(wallet), mempool.clone());

    let err = run_bump(
        &ctx,
        &parent,
        &anchor_strategy(&parent),
        &mut CpfpHandle::default(),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, CpfpError::WalletSigner(_)), "got {err:?}");
    assert_eq!(mempool.submissions(), 0);
}

/// A child with no fee must not reach a signer or the network.
#[tokio::test]
async fn a_child_with_no_readable_fee_fails_before_signing() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let mut psbt = synthetic_child_psbt(&parent, 0);
    psbt.inputs[1].witness_utxo = None;
    let wallet = Arc::new(FakeWallet::returning(psbt, Vec::new()));
    let mempool = Arc::new(FakeMempool::ok());
    let ctx = contention_context(wallet.clone(), mempool.clone());

    let err = run_bump(
        &ctx,
        &parent,
        &anchor_strategy(&parent),
        &mut CpfpHandle::default(),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, CpfpError::MalformedChild(_)), "got {err:?}");
    assert!(wallet.sign_requests.lock().unwrap().is_empty());
    assert_eq!(mempool.submissions(), 0);
}

/// An accepted replacement frees the inputs of the child it replaced.
#[tokio::test]
async fn an_accepted_replacement_takes_over_from_the_live_child() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let outpoint = |vout| OutPoint::new(parent.compute_txid(), vout);
    let ours = Txid::from_byte_array([0xAA; 32]);
    let wallet = Arc::new(FakeWallet::returning(
        synthetic_child_psbt(&parent, 0),
        vec![outpoint(7)],
    ));
    let ctx = contention_context(
        wallet.clone(),
        Arc::new(
            FakeMempool::ok().with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(5))),
        ),
    );
    let mut handle = seeded_handle(&wallet, &[outpoint(8)], ours);

    let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .expect("the replacement must submit");

    assert_eq!(bumped, BumpOutcome::Submitted);
    assert_eq!(*wallet.released.lock().unwrap(), vec![outpoint(8)]);
    assert_eq!(held_by(&handle), vec![outpoint(7)]);
    assert_ne!(handle.accepted_txid(), Some(ours));
}

/// A live child under the target hands its size, its fee, the cap and its inputs to the
/// build, whoever built it.
#[tokio::test]
async fn a_child_of_ours_below_the_target_is_outbid_with_its_own_inputs() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let outpoint = |vout| OutPoint::new(parent.compute_txid(), vout);
    let ours = Txid::from_byte_array([0xAA; 32]);
    let wallet = Arc::new(FakeWallet::returning(
        synthetic_child_psbt(&parent, 0),
        vec![outpoint(7)],
    ));
    let ctx = contention_context(
        wallet.clone(),
        Arc::new(
            FakeMempool::ok().with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(5))),
        ),
    );
    let mut handle = seeded_handle(&wallet, &[outpoint(8)], ours);

    run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .expect("the replacement must submit");

    assert_eq!(
        wallet.last_build(),
        Some(RecordedBuild {
            target: FeeRate::from_sat_per_vb(8).unwrap(),
            inputs: vec![outpoint(8)],
            incumbent: Some(incumbent_of_child_at()),
        })
    );
}

/// A foreign child below the target sets the price of the build. The inputs of our beaten
/// child stay available to that build, and no lookup makes the foreign child ours.
#[tokio::test]
async fn a_foreign_child_below_the_target_is_outbid() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let outpoint = |vout| OutPoint::new(parent.compute_txid(), vout);
    let ours = Txid::from_byte_array([0xAA; 32]);
    let theirs = Txid::from_byte_array([0xBB; 32]);
    let wallet = Arc::new(FakeWallet::returning(
        synthetic_child_psbt(&parent, 0),
        vec![outpoint(7)],
    ));
    let ctx = contention_context(
        wallet.clone(),
        Arc::new(
            FakeMempool::ok().with_probe(child_at(theirs, FeeRate::from_sat_per_vb_unchecked(5))),
        ),
    );
    let mut handle = seeded_handle(&wallet, &[outpoint(8)], ours);

    let bumped = run_bump(
        &ctx,
        &parent,
        &multi_anchor_strategy(&parent, anchor_key),
        &mut handle,
    )
    .await
    .expect("the outbid must submit");

    assert_eq!(bumped, BumpOutcome::Submitted);
    let build = wallet.last_build().expect("the ladder must build");
    assert_eq!(build.inputs, vec![outpoint(8)]);
    assert_eq!(build.incumbent, Some(incumbent_of_child_at()));
}

/// A replacement above the cap is refused. Nothing is signed or submitted, the live child
/// keeps its lease, and the parent counts as live.
#[tokio::test]
async fn a_replacement_above_the_cap_leaves_the_live_child_in_place() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let inputs = [OutPoint::new(parent.compute_txid(), 8)];
    let ours = Txid::from_byte_array([0xAA; 32]);
    let wallet = Arc::new(FakeWallet::above_cap());
    let mempool = Arc::new(
        FakeMempool::ok().with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(5))),
    );
    let ctx = contention_context(wallet.clone(), mempool.clone());
    let mut handle = seeded_handle(&wallet, &inputs, ours);

    let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .expect("a refusal is not an error");

    assert_eq!(bumped, BumpOutcome::ParentIsLive);
    assert_eq!(mempool.submissions(), 0);
    assert!(wallet.released.lock().unwrap().is_empty());
    assert_eq!(held_by(&handle), inputs.to_vec());
}

/// A foreign child that the cap keeps this operator from outbidding ends the attempt, so the
/// inputs of our beaten child go back to the wallet.
#[tokio::test]
async fn a_refused_outbid_of_a_foreign_child_frees_the_beaten_child() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let inputs = [OutPoint::new(parent.compute_txid(), 8)];
    let wallet = Arc::new(FakeWallet::above_cap());
    let ctx = contention_context(
        wallet.clone(),
        Arc::new(FakeMempool::ok().with_probe(child_at(
            Txid::from_byte_array([0xBB; 32]),
            FeeRate::from_sat_per_vb_unchecked(5),
        ))),
    );
    let mut handle = seeded_handle(&wallet, &inputs, Txid::from_byte_array([0xAA; 32]));

    let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .expect("a refusal is not an error");

    assert_eq!(bumped, BumpOutcome::ParentIsLive);
    assert_eq!(*wallet.released.lock().unwrap(), inputs.to_vec());
}

/// With no live child, nothing shows that a mempool holds the parent, so a refusal at the cap
/// must not read as proof of life.
#[tokio::test]
async fn a_refusal_with_no_live_child_does_not_report_a_live_parent() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let mempool = Arc::new(FakeMempool::ok().with_probe(ParentProbe::Absent));
    let ctx = contention_context(Arc::new(FakeWallet::above_cap()), mempool.clone());

    let outcome = ctx
        .bump(
            &parent,
            &anchor_strategy(&parent),
            &mut CpfpHandle::default(),
        )
        .await;

    assert_eq!(outcome, BumpOutcome::NoPackage);
    assert_eq!(mempool.submissions(), 0);
}

/// A candidate on a spent output would come back through the replaced inputs and fail the
/// same way on every trigger. A plain rejection clears the slot, so the next build selects
/// from what the wallet lists.
#[tokio::test]
async fn a_plain_rejection_clears_a_stale_candidate() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let stale = OutPoint::new(parent.compute_txid(), 8);
    let wallet = Arc::new(FakeWallet::returning(
        synthetic_child_psbt(&parent, 0),
        Vec::new(),
    ));
    let ctx = contention_context(
        wallet.clone(),
        Arc::new(FakeMempool::failing("package-not-valid")),
    );
    let mut handle = seeded_handle(&wallet, &[stale], Txid::from_byte_array([0xAA; 32]));

    run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .unwrap_err();
    assert_eq!(wallet.last_build().unwrap().inputs, vec![stale]);
    assert!(held_by(&handle).is_empty());

    run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .unwrap_err();
    assert_eq!(wallet.last_build().unwrap().inputs, Vec::new());
}

/// One slot holds the candidate. A newer child with an unknown result takes it over, and the
/// lease of the older one drops.
#[tokio::test]
async fn a_newer_child_with_an_unknown_result_takes_over_the_candidate_slot() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let older = OutPoint::new(parent.compute_txid(), 8);
    let newer = OutPoint::new(parent.compute_txid(), 7);
    let wallet = Arc::new(FakeWallet::returning(
        synthetic_child_psbt(&parent, 0),
        vec![newer],
    ));
    let ctx = contention_context(
        wallet.clone(),
        Arc::new(FakeMempool::with_result(SubmitResult::Unknown)),
    );
    let mut handle = seeded_handle(&wallet, &[older], Txid::from_byte_array([0xAA; 32]));

    run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .unwrap_err();

    assert_eq!(held_by(&handle), vec![newer]);
    assert_eq!(*wallet.released.lock().unwrap(), vec![older]);
}

/// With a live child recorded, a failed probe leaves nothing to price against. The build
/// waits, and the outcome does not claim a parent that no probe read.
#[tokio::test]
async fn a_failed_probe_skips_the_build_when_the_handle_records_a_live_child() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let inputs = [OutPoint::new(parent.compute_txid(), 8)];
    let ours = Txid::from_byte_array([0xAA; 32]);
    let wallet = Arc::new(FakeWallet::failing("the build must wait"));
    let mempool = Arc::new(FakeMempool::ok().with_failing_probe("probe RPC failure"));
    let ctx = contention_context(wallet.clone(), mempool.clone());
    let mut handle = seeded_handle(&wallet, &inputs, ours);

    let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .expect("a failed probe is not an error");

    assert_eq!(bumped, BumpOutcome::NoPackage);
    assert!(wallet.builds.lock().unwrap().is_empty());
    assert_eq!(held_by(&handle), inputs.to_vec());
}

/// A child that left the mempool is not an incumbent. Its inputs stay available, because the
/// wallet can still hide them.
#[tokio::test]
async fn a_build_after_a_child_left_the_mempool_has_no_incumbent() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let outpoint = |vout| OutPoint::new(parent.compute_txid(), vout);
    let ours = Txid::from_byte_array([0xAA; 32]);
    let wallet = Arc::new(FakeWallet::returning(
        synthetic_child_psbt(&parent, 0),
        vec![outpoint(7)],
    ));
    let ctx = contention_context(wallet.clone(), Arc::new(FakeMempool::ok()));
    let mut handle = seeded_handle(&wallet, &[outpoint(8)], ours);

    run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .expect("the rebuild must submit");

    let build = wallet.last_build().expect("the ladder must build");
    assert_eq!(build.incumbent, None);
    assert_eq!(build.inputs, vec![outpoint(8)]);
}

/// After a restart the handle is empty and our child is in the mempool. The ladder adopts it:
/// the handle takes its identity and a lease on its wallet inputs, and it stands.
#[tokio::test]
async fn an_empty_handle_adopts_our_live_child() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let ours = Txid::from_byte_array([0xAA; 32]);
    let wallet = Arc::new(FakeWallet {
        owns_children: true,
        ..FakeWallet::failing("the live child meets the target")
    });
    let ctx = contention_context(
        wallet.clone(),
        Arc::new(
            FakeMempool::ok().with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(10))),
        ),
    );
    let mut handle = CpfpHandle::default();

    let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .expect("an adopted child ends the attempt");

    assert_eq!(bumped, BumpOutcome::ParentIsLive);
    assert_eq!(handle.accepted_txid(), Some(ours));
    assert_eq!(
        held_by(&handle),
        vec![OutPoint::new(Txid::from_byte_array([0xCC; 32]), 0)]
    );
}

/// A small wallet can only fund the replacement of an adopted child from that child's own
/// inputs, so they reach the same attempt's build.
#[tokio::test]
async fn an_adopted_child_below_the_target_passes_its_inputs_to_the_build() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let ours = Txid::from_byte_array([0xAA; 32]);
    let wallet = Arc::new(FakeWallet {
        owns_children: true,
        ..FakeWallet::returning(synthetic_child_psbt(&parent, 0), Vec::new())
    });
    let ctx = contention_context(
        wallet.clone(),
        Arc::new(
            FakeMempool::ok().with_probe(child_at(ours, FeeRate::from_sat_per_vb_unchecked(5))),
        ),
    );

    run_bump(
        &ctx,
        &parent,
        &anchor_strategy(&parent),
        &mut CpfpHandle::default(),
    )
    .await
    .expect("the replacement must submit");

    let build = wallet.last_build().expect("the ladder must build");
    assert_eq!(
        build.inputs,
        vec![OutPoint::new(Txid::from_byte_array([0xCC; 32]), 0)]
    );
    assert_eq!(build.incumbent, Some(incumbent_of_child_at()));
}

/// With no answer on who owns the live child, nothing is released. The next attempt reads
/// it again.
#[tokio::test]
async fn a_failed_child_lookup_releases_nothing() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let inputs = [OutPoint::new(parent.compute_txid(), 8)];
    let wallet = Arc::new(FakeWallet::failing("the live child meets the target"));
    let mempool = FakeMempool {
        inputs_fail: true,
        ..FakeMempool::ok()
    }
    .with_probe(child_at(
        Txid::from_byte_array([0xBB; 32]),
        FeeRate::from_sat_per_vb_unchecked(10),
    ));
    let ctx = contention_context(wallet.clone(), Arc::new(mempool));
    let mut handle = seeded_handle(&wallet, &inputs, Txid::from_byte_array([0xAA; 32]));

    let bumped = run_bump(&ctx, &parent, &anchor_strategy(&parent), &mut handle)
        .await
        .expect("the live child ends the attempt");

    assert_eq!(bumped, BumpOutcome::ParentIsLive);
    assert!(wallet.released.lock().unwrap().is_empty());
    assert_eq!(held_by(&handle), inputs.to_vec());
}

/// The node refuses a package below its minimum when the parent is not in the mempool, so
/// the minimum lifts the target there, and only there.
#[tokio::test]
async fn the_node_minimum_lifts_the_target_only_for_an_absent_parent() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let minimum = FeeRate::from_sat_per_vb(15).unwrap();

    for (probe, expected, reads) in [
        (ParentProbe::Absent, minimum, 1),
        (
            ParentProbe::NoChild,
            FeeRate::from_sat_per_vb(8).unwrap(),
            0,
        ),
    ] {
        let wallet = Arc::new(FakeWallet::returning(
            synthetic_child_psbt(&parent, 0),
            Vec::new(),
        ));
        let mempool = Arc::new(
            FakeMempool {
                min_fee_rate: Some(minimum),
                ..FakeMempool::ok()
            }
            .with_probe(probe),
        );
        let ctx = contention_context(wallet.clone(), mempool.clone());

        run_bump(
            &ctx,
            &parent,
            &anchor_strategy(&parent),
            &mut CpfpHandle::default(),
        )
        .await
        .expect("the package must submit");

        assert_eq!(wallet.target(), Some(expected), "probe = {probe:?}");
        assert_eq!(*mempool.min_fee_reads.lock().unwrap(), reads);
    }
}

/// A failed read of the minimum does not stop the bump.
#[tokio::test]
async fn a_failed_read_of_the_node_minimum_prices_from_the_estimate() {
    let (_, anchor_key) = test_keypair_and_xonly();
    let parent = synthetic_parent(anchor_key, Amount::from_sat(330));
    let wallet = Arc::new(FakeWallet::returning(
        synthetic_child_psbt(&parent, 0),
        Vec::new(),
    ));
    let mempool = FakeMempool {
        min_fee_rate: None,
        ..FakeMempool::ok()
    }
    .with_probe(ParentProbe::Absent);
    let ctx = contention_context(wallet.clone(), Arc::new(mempool));

    run_bump(
        &ctx,
        &parent,
        &anchor_strategy(&parent),
        &mut CpfpHandle::default(),
    )
    .await
    .expect("the package must submit");

    assert_eq!(wallet.target(), Some(FeeRate::from_sat_per_vb(8).unwrap()));
}

/// A constant-byte signer whose output is recognisable in the final witness, so a test can
/// prove *which* signer produced a given signature rather than only that signing happened.
fn fake_input_signer_const(byte: u8) -> InputSigner {
    Arc::new(move |_msg: Message| {
        Box::pin(async move {
            Ok::<_, SignerError>(
                Signature::from_slice(&[byte; 64]).expect("64 bytes is a valid sig"),
            )
        })
    })
}

/// The script-path bump must (a) route the anchor input through the
/// dedicated `multi_anchor_signer` — NOT the tap-tweaked key-path signer — and (b) emit the
/// BIP-341 script-path witness stack `[signature, leaf_script, control_block]` in exactly
/// that order. A wrong signer or a reordered stack produces a transaction that fails script
/// validation at broadcast, on the time-critical contest path, with no local signal.
///
/// Sentinels make routing observable: the key-path signer errors if invoked at all, and the
/// multi-anchor signer returns a recognisable constant signature that is then asserted
/// byte-for-byte in the captured child.
#[tokio::test]
async fn multi_anchor_bump_routes_untweaked_signer_and_orders_witness() {
    use bitcoin::taproot::TaprootBuilder;

    // Two watchtower-style leaves; ours is leaf 0.
    let (_, our_key) = test_keypair_and_xonly();
    let derived_key = |seed: u8| {
        let sk = bitcoin::secp256k1::SecretKey::from_slice(&[seed; 32]).expect("valid scalar");
        bitcoin::secp256k1::Keypair::from_secret_key(SECP256K1, &sk)
            .x_only_public_key()
            .0
    };
    let other_key = derived_key(0x11);
    let leaf = |key: XOnlyPublicKey| {
        bitcoin::script::Builder::new()
            .push_slice(key.serialize())
            .push_opcode(bitcoin::opcodes::all::OP_CHECKSIG)
            .into_script()
    };
    let our_leaf = leaf(our_key);
    let spend_info = TaprootBuilder::new()
        .add_leaf(1, our_leaf.clone())
        .expect("depth 1 is valid")
        .add_leaf(1, leaf(other_key))
        .expect("depth 1 is valid")
        .finalize(SECP256K1, derived_key(0x22))
        .expect("tree finalizes");
    let control_block = spend_info
        .control_block(&(our_leaf.clone(), bitcoin::taproot::LeafVersion::TapScript))
        .expect("leaf is in the tree");
    let anchor_spk = bitcoin::ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

    let parent = Transaction {
        version: Version(3),
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(330),
            script_pubkey: anchor_spk,
        }],
    };
    // The synthetic child spends parent:0 (the anchor) + one wallet funding input.
    let psbt = synthetic_child_psbt(&parent, 0);
    let wallet_funding = vec![OutPoint {
        txid: parent.compute_txid(),
        vout: 9,
    }];

    let mempool = Arc::new(FakeMempool::ok());
    let ctx = CpfpContext {
        wallet: Arc::new(FakeWallet::returning(psbt, wallet_funding.clone())),
        fee_source: Arc::new(FakeFeeSource::returning(
            FeeRate::from_sat_per_vb(10).unwrap(),
        )),
        // Key-path signer must never fire for a script-path anchor: if it does, the bump
        // errors and the assertions below fail loudly.
        anchor_input_signer: fake_input_signer_failing(
            "key-path anchor signer must not be called for a multi-anchor spend",
        ),
        multi_anchor_signer: fake_input_signer_const(0xAA),
        wallet_input_signer: fake_input_signer_const(0xBB),
        // Neutral fee settings: this test pins signer selection, not pricing.
        policy: FeeTargetPolicy {
            premium_percent: 0,
            min_package_fee_rate: FeeRate::ZERO,
            max_fee_rate: FeeRate::from_sat_per_vb(20).unwrap(),
        },
        mempool: mempool.clone(),
    };
    let strategy = CpfpStrategy {
        spend: ChildSpend::multi_anchor(
            OutPoint::new(parent.compute_txid(), 0),
            our_leaf.clone(),
            control_block.clone(),
        ),
        parent_fee: Amount::from_sat(200),
        deadline: DeadlineClass::NoDeadline,
        first_bump: FirstBump::AtPublish,
    };
    let mut handle = CpfpHandle::default();
    let submitted = run_bump(&ctx, &parent, &strategy, &mut handle)
        .await
        .expect("script-path bump must succeed");
    assert_eq!(submitted, BumpOutcome::Submitted);
    assert_eq!(held_by(&handle), wallet_funding);

    let packages = mempool.captured.lock().unwrap();
    let child = &packages[0][1];

    // Anchor input: exactly the BIP-341 script-path stack, in order, signed by the
    // multi-anchor sentinel.
    let anchor_witness: Vec<&[u8]> = child.input[0].witness.iter().collect();
    assert_eq!(
        anchor_witness.len(),
        3,
        "script-path witness must be [sig, leaf_script, control_block]"
    );
    assert_eq!(
        anchor_witness[0], &[0xAA; 64],
        "anchor signature must come from multi_anchor_signer, not the key-path signer"
    );
    assert_eq!(anchor_witness[1], our_leaf.as_bytes());
    assert_eq!(anchor_witness[2], control_block.serialize().as_slice());

    // Wallet funding input stays a bare key-path spend via the wallet signer.
    let wallet_witness: Vec<&[u8]> = child.input[1].witness.iter().collect();
    assert_eq!(wallet_witness.len(), 1);
    assert_eq!(wallet_witness[0], &[0xBB; 64]);
}

/// A replacement rejection of the child proves nothing about the parent: the child also spends
/// wallet inputs, and the rejection can come from any of them. Only the probe shows the
/// parent. A rejection of the parent itself overrides the probe: a conflict holds its place.
#[tokio::test]
async fn a_rejected_child_reports_the_probe_and_a_rejected_parent_does_not() {
    let (_, key) = test_keypair_and_xonly();
    let parent = synthetic_parent(key, Amount::from_sat(330));
    let parent_txid = parent.compute_txid();
    let child = Txid::from_byte_array([0xEE; 32]);
    let funding = vec![OutPoint {
        txid: parent_txid,
        vout: 7,
    }];
    let marker = "insufficient fee, rejecting replacement";

    for (rejected, probe, expected) in [
        (parent_txid, ParentProbe::Absent, BumpOutcome::NoPackage),
        (parent_txid, ParentProbe::NoChild, BumpOutcome::NoPackage),
        (child, ParentProbe::Absent, BumpOutcome::NoPackage),
        (child, ParentProbe::NoChild, BumpOutcome::ParentIsLive),
    ] {
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            Arc::new(FakeWallet::returning(
                synthetic_child_psbt(&parent, 0),
                funding.clone(),
            )),
            Arc::new(
                FakeMempool::failing("package rbf failure")
                    .with_tx_error(rejected, marker)
                    .with_probe(probe),
            ),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let outcome = ctx
            .bump(
                &parent,
                &anchor_strategy(&parent),
                &mut CpfpHandle::default(),
            )
            .await;
        assert_eq!(
            outcome, expected,
            "rejected = {rejected}, probe = {probe:?}"
        );
    }
}

/// A failed attempt on a parent that the probe read in the mempool reports a live parent, so
/// no duty fails and no bare resubmission runs for it.
#[tokio::test]
async fn a_failed_attempt_on_a_parent_in_the_mempool_reports_it_live() {
    let (_, key) = test_keypair_and_xonly();
    let parent = synthetic_parent(key, Amount::from_sat(330));
    let psbt = synthetic_child_psbt(&parent, 0);
    let no_funds = FakeWallet::failing("no funds now");
    let bad_signer = FakeWallet {
        sign_error: Some(SignerError("vault offline".to_string())),
        ..FakeWallet::returning(psbt.clone(), Vec::new())
    };
    let rejected = FakeWallet::returning(psbt, Vec::new());

    for (wallet, mempool) in [
        (no_funds, FakeMempool::ok()),
        (bad_signer, FakeMempool::ok()),
        (rejected, FakeMempool::failing("package-not-valid")),
    ] {
        let ctx = contention_context(Arc::new(wallet), Arc::new(mempool));
        let outcome = ctx
            .bump(
                &parent,
                &anchor_strategy(&parent),
                &mut CpfpHandle::default(),
            )
            .await;
        assert_eq!(outcome, BumpOutcome::ParentIsLive);
    }
}

/// A parent that meets the target reports what the probe read.
#[tokio::test]
async fn a_parent_that_needs_no_child_reports_what_the_probe_read() {
    let (_, key) = test_keypair_and_xonly();
    let parent = synthetic_parent(key, Amount::from_sat(330));
    let strategy = CpfpStrategy {
        parent_fee: Amount::from_sat(1_000_000),
        ..anchor_strategy(&parent)
    };

    for (probe, expected) in [
        (ParentProbe::NoChild, BumpOutcome::ParentIsLive),
        (ParentProbe::Absent, BumpOutcome::NoPackage),
    ] {
        let ctx = contention_context(
            Arc::new(FakeWallet::failing("no build")),
            Arc::new(FakeMempool::ok().with_probe(probe)),
        );
        let outcome = ctx
            .bump(&parent, &strategy, &mut CpfpHandle::default())
            .await;
        assert_eq!(outcome, expected);
    }
}

/// A wallet that reports a permanent failure stops the bumps, and a transient failure
/// leaves the parent to the next trigger.
#[tokio::test]
async fn a_permanent_wallet_failure_reads_as_unbumpable() {
    let (_, key) = test_keypair_and_xonly();
    let parent = synthetic_parent(key, Amount::from_sat(330));

    for (wallet, expected) in [
        (
            FakeWallet::unbumpable("anchor vout 9 out of range"),
            BumpOutcome::Unbumpable,
        ),
        (FakeWallet::failing("no funds now"), BumpOutcome::NoPackage),
    ] {
        let ctx = context(
            Arc::new(FakeFeeSource::returning(
                FeeRate::from_sat_per_vb(10).unwrap(),
            )),
            Arc::new(wallet),
            Arc::new(
                FakeMempool::failing("mempool must not be called").with_probe(ParentProbe::Absent),
            ),
            fake_input_signer_ok(),
            fake_input_signer_ok(),
            FeeRate::from_sat_per_vb(20).unwrap(),
        );
        let outcome = ctx
            .bump(
                &parent,
                &anchor_strategy(&parent),
                &mut CpfpHandle::default(),
            )
            .await;
        assert_eq!(outcome, expected);
    }
}
