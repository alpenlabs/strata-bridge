//! Shared Bitcoin chain helpers for executors.

use bitcoin::{
    Address, Amount, OutPoint, Script, ScriptBuf, Transaction, TxOut, Txid, secp256k1::SECP256K1,
    taproot::ControlBlock,
};
use bitcoind_async_client::{Client as BitcoinClient, error::ClientError, traits::Reader};
use btc_tracker::{cpfp::CpfpStrategy, event::TxStatus, tx_driver::TxDriver};
use strata_bridge_tx_graph::fee;
use tracing::{debug, error, info, warn};

use crate::{errors::ExecutorError, output_handles::OutputHandles};

/// How the publish path learns the exact fee that a parent pays.
///
/// The CPFP child pays the difference between what the parent already paid and what the
/// package target asks for, so a wrong value here makes the child overpay or underpay.
///
/// [`Self::Floor`] derives the fee from the transaction that it publishes. That removes the
/// one mistake a caller-computed value allows: a fee derived from a different transaction
/// than the one that reaches the network.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ParentFee {
    /// The parent pays the bridge protocol floor rate, so its fee is `vsize × FEE_RATE` by
    /// construction. Every presigned bridge transaction is in this class.
    Floor,
    /// The caller funded the parent and knows the fee that it paid. Wallet-funded
    /// transactions are in this class, because a wallet funds at the market rate and not at
    /// the protocol floor.
    Exact(Amount),
}

impl ParentFee {
    /// Resolves to the fee that `tx` pays.
    fn resolve(self, tx: &Transaction) -> Amount {
        match self {
            Self::Floor => parent_fee_for_floor_tx(tx),
            Self::Exact(fee) => fee,
        }
    }
}

/// Computes the fee paid by a tx that follows the bridge protocol floor rate
/// ([`fee::FEE_RATE`] = 2 sat/vB).
///
/// Cannot overflow in practice: `tx.vsize()` is bounded by the consensus 4 MWU limit, well
/// inside `u64`.
fn parent_fee_for_floor_tx(tx: &Transaction) -> Amount {
    // `Transaction::vsize()` returns `usize`. Both supported targets (x86_64, aarch64) have
    // `usize == u64`, but use `try_into` to avoid a silent truncation hazard if a future
    // 32-bit target ever ships a tx larger than `u32::MAX` vB (impossible in practice but
    // the lint cleanup is free).
    let vsize_vb: u64 = tx
        .vsize()
        .try_into()
        .expect("tx.vsize() fits in u64 on every supported target");
    fee::FEE_RATE
        .fee_vb(vsize_vb)
        .expect("protocol-floor × tx vsize cannot overflow Amount")
}

/// Scans `tx.output` for the first output paying the operator's general-wallet receive script
/// and returns its outpoint, or `None` if no matching output exists.
///
/// The receive script is the backend's `general_script_pubkey`: the BIP86-tweaked
/// `tr(general_pubkey)` P2TR for the native BDK backend, or the vault P2WPKH
/// for the Fireblocks backend. Both backends draw their funding change to this script, so this
/// is what `InferGeneralPayout` must match — using a hardcoded P2TR derivation would silently
/// miss the Fireblocks change output and disable CPFP for that backend.
///
/// Used by [`CpfpKind::InferGeneralPayout`] to opportunistically classify a tx as
/// `PayoutCombined` when an operator-owned output happens to be present. Three call sites
/// rely on this:
///
/// - **Withdrawal fulfillment**: the wallet adds a change output back to the general wallet at
///   `WithdrawalFulfillmentTx::OPTIONAL_CHANGE_VOUT` (vout 2) when selected inputs exceed
///   user_amount + fee. When change exists, CPFP via that output.
/// - **Stake funding**: the wallet adds a change output back to the general wallet (vout depends on
///   ordering, typically vout 1 after the reserved-wallet output at vout 0).
/// - **Slash**: the calling watchtower's payout sits at `vout = 1 + their_index_in_watchtowers`,
///   keyed to its params-file covenant `payout_descriptor`. This is found only when that
///   descriptor's script equals the general-wallet receive script — which is exactly what the
///   native `payout_descriptor()` returns, so the scan matches whenever the params descriptor
///   agrees with the wallet (the orchestrator warns at startup when it doesn't). On a mismatch (or
///   a Fireblocks vault script, which is not the general P2TR) the scan returns `None` and slash
///   CPFP falls back to no-bump (see `publish_slash`).
///
/// Brittle assumption: matches by exact `script_pubkey` equality. If two different
/// operators happened to share the same receive script, the first match wins — but each
/// operator has a unique general-wallet key/vault in practice, so this can't collide in
/// production.
pub(crate) async fn first_general_payout_outpoint(
    tx: &Transaction,
    output_handles: &OutputHandles,
) -> Option<OutPoint> {
    let expected_script = output_handles.wallet.read().await.general_script_pubkey();
    first_output_paying_script(tx, &expected_script)
}

/// Validates the caller-named anchor and returns the CPFP strategy for it.
///
/// `anchor_key` comes from the anchor connector of the transaction that the caller published.
/// A duty carries the key when the state machine builds the transaction. `signing_key` is the
/// key that this operator can produce a signature for. A child of an anchor keyed to any other
/// key carries a signature that no mempool accepts, so the two must match.
///
/// The caller names the vout from its tx type's own constant, so a mismatch there is a code
/// defect: the constant and the builder disagree. The check compares the output's script
/// against the anchor script and its value against the anchor dust floor. The value check is
/// `>=`, not `==` — `CounterproofAckTx` folds its input connectors' residual into the anchor,
/// so that anchor carries two times the dust value.
///
/// On a mismatch this logs at error level and returns `None`. The transaction still
/// publishes: it is signed and the protocol needs it on chain. Only the bump path is lost,
/// and the error names exactly what to fix.
fn checked_anchor_strategy(
    tx: &Transaction,
    anchor_vout: u32,
    anchor_key: bitcoin::XOnlyPublicKey,
    signing_key: bitcoin::XOnlyPublicKey,
    network: bitcoin::Network,
    parent_fee: Amount,
    label: &str,
) -> Option<CpfpStrategy> {
    let txid = tx.compute_txid();
    if anchor_key != signing_key {
        error!(
            %txid,
            %label,
            anchor_vout,
            %anchor_key,
            %signing_key,
            "anchor is keyed to a key this operator cannot sign with; publishing without CPFP"
        );
        return None;
    }
    let expected_script = Address::p2tr(SECP256K1, anchor_key, None, network).script_pubkey();
    let expected_value = fee::anchor_dust_value();
    let Some(output) = tx.output.get(anchor_vout as usize) else {
        error!(
            %txid,
            %label,
            anchor_vout,
            n_outputs = tx.output.len(),
            "anchor vout is out of range; publishing without CPFP"
        );
        return None;
    };
    if output.script_pubkey != expected_script || output.value < expected_value {
        error!(
            %txid,
            %label,
            anchor_vout,
            output_value = %output.value,
            expected_min_value = %expected_value,
            script_matches = output.script_pubkey == expected_script,
            "named output is not the anchor that the caller named; publishing without CPFP"
        );
        return None;
    }
    Some(CpfpStrategy::AnchorBearing {
        anchor_vout,
        anchor_internal_key: anchor_key,
        parent_fee,
    })
}

/// Inner helper for [`first_general_payout_outpoint`]; takes the receive script explicitly so
/// it can be unit-tested without constructing a full [`OutputHandles`].
fn first_output_paying_script(tx: &Transaction, expected_script: &Script) -> Option<OutPoint> {
    let txid = tx.compute_txid();
    tx.output.iter().enumerate().find_map(|(vout, o)| {
        if o.script_pubkey != *expected_script {
            return None;
        }
        u32::try_from(vout).ok().map(|vout| OutPoint { txid, vout })
    })
}

/// Computes the exact fee paid by `tx` from its input `prevouts` (in input order). Returns
/// `None` if the input or output sum overflows `Amount` or if outputs exceed inputs (an
/// invariant violation in a real tx, but explicitly fallible here so callers can surface
/// the error instead of panicking on an unexpected state).
///
/// Used by wallet-funded callers (withdrawal fulfillment, stake funding, unstaking intent
/// funding) where the fee rate is whatever BDK chose, not the bridge protocol floor.
pub(crate) fn exact_fee_from_prevouts(prevouts: &[TxOut], tx: &Transaction) -> Option<Amount> {
    let inputs_sum = prevouts
        .iter()
        .try_fold(Amount::ZERO, |acc, o| acc.checked_add(o.value))?;
    let outputs_sum = tx
        .output
        .iter()
        .try_fold(Amount::ZERO, |acc, o| acc.checked_add(o.value))?;
    inputs_sum.checked_sub(outputs_sum)
}

/// Returns whether the provided transaction ID already exists on chain (confirmed or in the
/// mempool).
pub(crate) async fn is_txid_onchain(
    bitcoind_rpc_client: &BitcoinClient,
    txid: &Txid,
) -> Result<bool, ClientError> {
    debug!(%txid, "checking if tx is on chain");
    match bitcoind_rpc_client
        .get_raw_transaction_verbosity_one(txid)
        .await
    {
        Ok(_) => Ok(true),
        Err(e) if e.is_tx_not_found() => Ok(false),
        Err(e) => {
            warn!(%txid, ?e, "could not determine if tx is on chain");
            Err(e)
        }
    }
}

/// Returns whether `outpoint` is currently unspent on chain or in the mempool.
///
/// Wraps Bitcoin Core's `gettxout`. A `null` result (spent or non-existent UTXO) maps to
/// `Ok(false)`; transport, RPC, or parse failures propagate as `Err` so callers do not mistake a
/// transient blip for a confirmed spend.
pub(crate) async fn is_outpoint_unspent(
    bitcoind_rpc_client: &BitcoinClient,
    outpoint: &OutPoint,
) -> Result<bool, ClientError> {
    debug!(%outpoint, "checking if outpoint is unspent");
    match bitcoind_rpc_client
        .get_tx_out(&outpoint.txid, outpoint.vout, true)
        .await
    {
        Ok(_) => Ok(true),
        // bitcoind returns `null` for a spent or non-existent UTXO; the client surfaces that
        // through this specific `Other` variant because the JSON-RPC response carries no `result`
        // field.
        Err(ClientError::Other(ref msg)) if msg == "Empty data received" => Ok(false),
        Err(e) => {
            warn!(%outpoint, ?e, "could not determine if outpoint is unspent");
            Err(e)
        }
    }
}

/// Returns whether chain state shows the persisted withdrawal-funding `outpoints` were
/// written under a previous general-wallet backend: every outpoint is unspent (mempool
/// included) AND none of them pays `current_general_spk`.
///
/// Every ambiguous outcome resolves to "not a previous-backend row" because the caller's
/// discard-and-reselect on a false positive funds, signs, and broadcasts a second payout,
/// while a false negative is a stuck row an operator can edit with the funds intact:
///
/// - Any outpoint spent or unknown (`gettxout` null): most likely this deposit's own fulfillment
///   transaction is in the mempool or confirmed while its confirmation event has not reached the
///   state machine yet → `Ok(false)`, the caller keeps the row and the funding path no-ops and
///   retries.
/// - All unspent, but any pays the current backend's own script: the wallet view and the chain
///   disagree (backend cache lag, mempool eviction, reorg), not a backend switch → `Ok(false)`.
/// - All unspent at scripts other than the current backend's: the cross-backend recovery case →
///   `Ok(true)`, the caller may discard the row and reselect.
/// - Any RPC failure propagates as `Err`; the caller keeps the row.
pub(crate) async fn outpoints_belong_to_previous_backend(
    bitcoind_rpc_client: &BitcoinClient,
    outpoints: &[OutPoint],
    current_general_spk: &ScriptBuf,
) -> Result<bool, ClientError> {
    for outpoint in outpoints {
        debug!(%outpoint, "classifying persisted funding outpoint against chain state");
        match bitcoind_rpc_client
            .get_tx_out(&outpoint.txid, outpoint.vout, true)
            .await
        {
            Ok(res) => {
                if res.tx_out.script_pubkey == *current_general_spk {
                    return Ok(false);
                }
            }
            // Same mapping as `is_outpoint_unspent`: bitcoind returns `null` for a spent or
            // non-existent UTXO, surfaced by the client as this `Other` variant.
            Err(ClientError::Other(ref msg)) if msg == "Empty data received" => {
                return Ok(false);
            }
            Err(e) => {
                warn!(%outpoint, ?e, "could not classify persisted funding outpoint");
                return Err(e);
            }
        }
    }
    Ok(true)
}

/// Hint that lets the caller of [`publish_signed_transaction`] override how the CPFP
/// strategy is selected for a parent transaction.
///
/// - [`Self::AnchorAt`]: the parent carries an operator-keyed Taproot anchor at a vout that the
///   caller knows statically (each tx type exports its anchor vout as a constant). Applies to
///   claim/stake/unstaking_intent/counterproof/counterproof_ack and any other tx with a
///   `KeyedAnchor` connector. The publish helper checks the named output against the expected
///   anchor script and value before it enables CPFP.
/// - [`Self::PayoutCombined`] (for txs implementing
///   [`strata_bridge_connectors::ParentTxCombined`]): no keyed anchor; instead the caller-supplied
///   operator-owned output (`payout_outpoint`) is spent by the CPFP child. Applies to
///   cooperative_payout, uncontested_payout, contested_payout, unstaking, counterproof_nack — all
///   the txs whose payout vout is statically known to the caller.
/// - [`Self::InferGeneralPayout`]: scan the parent for the FIRST output paying the operator's
///   general-wallet script and use it as the CPFP payout. Applies to txs whose operator-owned
///   output isn't at a fixed vout — wallet-funded txs whose BDK change output may or may not exist
///   (withdrawal fulfillment, stake funding) and the slash tx (where the calling watchtower's vout
///   = `1 + their_index_in_filtered_watchtowers`, which we discover by script-match rather than
///   threading the index through). If no matching output exists, the helper falls back to
///   [`Self::None`].
/// - [`Self::None`]: broadcast as-is. Use only when the tx genuinely has no CPFP hook (deposit,
///   bridge proof).
#[derive(Debug, Clone)]
pub(crate) enum CpfpKind {
    /// The parent carries a keyed Taproot anchor at this vout.
    AnchorAt {
        /// Index of the anchor output on the parent. Callers pass the tx type's own
        /// constant (for example `StakeTx::CPFP_VOUT`), not a discovered value.
        anchor_vout: u32,
        /// Internal key of that anchor. Callers read it from the anchor connector of the
        /// transaction, through
        /// [`ParentTx::cpfp_connector`](strata_bridge_connectors::ParentTx::cpfp_connector).
        /// The key that reaches the bump is therefore the key that built the output. A duty
        /// whose transaction the state machine builds carries the key with it.
        anchor_key: bitcoin::XOnlyPublicKey,
    },
    /// Build the child by spending the given operator-owned output of the parent.
    PayoutCombined { payout_outpoint: OutPoint },
    /// Look for the first output paying the operator's general-wallet script and use it as
    /// the CPFP payout. Falls back to no-CPFP if no such output exists (e.g. BDK didn't add
    /// a change output).
    InferGeneralPayout,
    /// Bump a multi-leaf (`MultiAnchor`) anchor script-path, satisfying the leaf this operator
    /// is entitled to as a watchtower of the parent's graph.
    ///
    /// Used by `contest` and `bridge_proof_timeout`. The leaf this operator can satisfy
    /// depends on the graph's watchtower set and on this operator's slot in it. Only the
    /// state machine knows both, so the caller supplies the full spend data.
    MultiAnchor {
        /// Index of the anchor output on the parent.
        anchor_vout: u32,
        /// The leaf script this operator may satisfy.
        leaf_script: ScriptBuf,
        /// Control block proving the leaf's membership in the anchor's tree.
        control_block: ControlBlock,
    },
    /// No CPFP — broadcast as-is.
    None,
}

/// Publishes a signed transaction and waits for the configured status. The `cpfp` parameter
/// drives strategy selection — see [`CpfpKind`].
///
/// `parent_fee` states how to learn the exact fee that `signed_tx` pays — see [`ParentFee`].
/// A presigned bridge transaction passes [`ParentFee::Floor`]. A wallet-funded transaction
/// passes [`ParentFee::Exact`] with `Psbt::fee()`, which BDK fills because it populates
/// `witness_utxo` on every input, or with [`exact_fee_from_prevouts`] when the prevouts are
/// known explicitly.
pub(crate) async fn publish_signed_transaction(
    output_handles: &OutputHandles,
    signed_tx: &Transaction,
    label: &str,
    wait_condition: fn(&TxStatus) -> bool,
    parent_fee: ParentFee,
    cpfp: CpfpKind,
) -> Result<(), ExecutorError> {
    let parent_fee = parent_fee.resolve(signed_tx);
    let inference_based = matches!(cpfp, CpfpKind::InferGeneralPayout);
    let strategy = match cpfp {
        CpfpKind::AnchorAt {
            anchor_vout,
            anchor_key,
        } => checked_anchor_strategy(
            signed_tx,
            anchor_vout,
            anchor_key,
            output_handles.operator_musig2_pubkey,
            output_handles.network,
            parent_fee,
            label,
        ),
        CpfpKind::PayoutCombined { payout_outpoint } => Some(CpfpStrategy::ParentTxCombined {
            payout_outpoint,
            parent_fee,
        }),
        CpfpKind::InferGeneralPayout => first_general_payout_outpoint(signed_tx, output_handles)
            .await
            .map(|payout_outpoint| CpfpStrategy::ParentTxCombined {
                payout_outpoint,
                parent_fee,
            }),
        CpfpKind::MultiAnchor {
            anchor_vout,
            leaf_script,
            control_block,
        } => Some(CpfpStrategy::MultiAnchorBearing {
            anchor_vout,
            leaf_script,
            control_block,
            parent_fee,
        }),
        CpfpKind::None => None,
    };
    // `InferGeneralPayout` scans for an output that can legitimately be absent (BDK adds no
    // change output when the inputs match exactly). A miss is therefore a warn, not an
    // error, and the transaction publishes without CPFP. `AnchorAt` misses are logged as
    // errors inside `checked_anchor_strategy` — a named vout that fails validation is a
    // code defect, not an expected state.
    if strategy.is_none() && inference_based {
        warn!(
            txid = %signed_tx.compute_txid(),
            %label,
            "no output pays the operator's general-wallet script; publishing without CPFP"
        );
    }
    drive_with_optional_cpfp(
        &output_handles.tx_driver,
        signed_tx,
        label,
        wait_condition,
        strategy,
    )
    .await
}

async fn drive_with_optional_cpfp(
    tx_driver: &TxDriver,
    signed_tx: &Transaction,
    label: &str,
    wait_condition: fn(&TxStatus) -> bool,
    cpfp: Option<CpfpStrategy>,
) -> Result<(), ExecutorError> {
    let txid = signed_tx.compute_txid();
    let cpfp_enabled = cpfp.is_some();
    info!(%txid, %label, cpfp_enabled, "publishing transaction");

    let drive_result = match cpfp {
        Some(strategy) => {
            tx_driver
                .drive_with_cpfp(signed_tx.clone(), strategy, wait_condition)
                .await
        }
        None => tx_driver.drive(signed_tx.clone(), wait_condition).await,
    };
    drive_result.map_err(|e| {
        warn!(%txid, %label, ?e, "failed to publish transaction");
        ExecutorError::TxDriverErr(e)
    })?;

    info!(%txid, %label, "transaction reached target status");
    Ok(())
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxOut, Txid, absolute,
        consensus::encode::deserialize_hex,
        hashes::Hash,
        key::Secp256k1,
        secp256k1::{SECP256K1, SecretKey},
        transaction::Version,
    };
    use bitcoind_async_client::{Auth, Client as BitcoinClient, traits::Reader};
    use btc_tracker::cpfp::CpfpStrategy;
    use corepc_node::{Conf, Input, Node, Output};
    use strata_bridge_tx_graph::fee;

    use super::{
        checked_anchor_strategy, first_output_paying_script, is_outpoint_unspent, is_txid_onchain,
        outpoints_belong_to_previous_backend,
    };

    /// Per-coinbase reward on regtest before any halving.
    const REGTEST_COINBASE_AMOUNT: Amount = Amount::from_sat(50 * 100_000_000);

    fn xonly_from_seed(seed: u8) -> bitcoin::XOnlyPublicKey {
        let sk = SecretKey::from_slice(&[seed; 32]).unwrap();
        let kp = bitcoin::key::Keypair::from_secret_key(&Secp256k1::new(), &sk);
        kp.x_only_public_key().0
    }

    fn dummy_v3_tx(outputs: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version(3),
            lock_time: absolute::LockTime::ZERO,
            input: vec![],
            output: outputs,
        }
    }

    /// The caller names the anchor vout from its tx type's constant. The check accepts a
    /// correct anchor, accepts an anchor above the dust value (the counterproof-ACK shape,
    /// which carries two times dust), and rejects a wrong vout, a wrong script, and a value
    /// below dust. A rejection returns `None`: the tx publishes without CPFP.
    #[test]
    fn checked_anchor_accepts_named_anchor_and_rejects_mismatches() {
        let anchor_key = xonly_from_seed(1);
        let other_key = xonly_from_seed(2);
        let network = Network::Regtest;
        let anchor_script = Address::p2tr(SECP256K1, anchor_key, None, network).script_pubkey();
        let other_script = Address::p2tr(SECP256K1, other_key, None, network).script_pubkey();
        let dust = fee::anchor_dust_value();
        let parent_fee = Amount::from_sat(220);

        let tx = dummy_v3_tx(vec![
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: other_script,
            },
            TxOut {
                value: dust,
                script_pubkey: anchor_script.clone(),
            },
        ]);

        // Correct vout resolves to the strategy.
        let strategy =
            checked_anchor_strategy(&tx, 1, anchor_key, anchor_key, network, parent_fee, "t");
        assert!(matches!(
            strategy,
            Some(CpfpStrategy::AnchorBearing { anchor_vout: 1, .. })
        ));

        // An anchor above the dust value (counterproof-ACK shape) also resolves.
        let ack_tx = dummy_v3_tx(vec![TxOut {
            value: dust * 2,
            script_pubkey: anchor_script,
        }]);
        assert!(
            checked_anchor_strategy(&ack_tx, 0, anchor_key, anchor_key, network, parent_fee, "t")
                .is_some()
        );

        // A vout that names a non-anchor output is rejected.
        assert!(
            checked_anchor_strategy(&tx, 0, anchor_key, anchor_key, network, parent_fee, "t")
                .is_none()
        );
        // A vout past the outputs is rejected.
        assert!(
            checked_anchor_strategy(&tx, 9, anchor_key, anchor_key, network, parent_fee, "t")
                .is_none()
        );
        // A value below dust is rejected even on the right script.
        let low = dummy_v3_tx(vec![TxOut {
            value: dust - Amount::from_sat(1),
            script_pubkey: Address::p2tr(SECP256K1, anchor_key, None, network).script_pubkey(),
        }]);
        assert!(
            checked_anchor_strategy(&low, 0, anchor_key, anchor_key, network, parent_fee, "t")
                .is_none()
        );

        // An anchor keyed to a key this operator cannot sign with disables the bump. A child
        // of that anchor carries a signature that no mempool accepts.
        assert!(
            checked_anchor_strategy(&tx, 1, anchor_key, other_key, network, parent_fee, "t")
                .is_none(),
            "an anchor key that this operator cannot sign with must disable the bump"
        );
    }

    #[test]
    fn first_payout_finds_matching_output_at_first_match() {
        let our_key = xonly_from_seed(1);
        let other_key = xonly_from_seed(2);
        let our_script = Address::p2tr(SECP256K1, our_key, None, Network::Regtest).script_pubkey();
        let other_script =
            Address::p2tr(SECP256K1, other_key, None, Network::Regtest).script_pubkey();
        let tx = dummy_v3_tx(vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            }, // vout 0: OP_RETURN-style placeholder
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: other_script,
            }, // vout 1: other key
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: our_script.clone(),
            }, // vout 2: our key
        ]);
        let found = first_output_paying_script(&tx, &our_script).expect("should find our output");
        assert_eq!(found.vout, 2);
    }

    #[test]
    fn first_payout_returns_none_when_no_match() {
        // WFT funding-without-change case: BDK didn't add a change output, so no operator
        // output exists on this tx.
        let our_key = xonly_from_seed(1);
        let other_key = xonly_from_seed(2);
        let our_script = Address::p2tr(SECP256K1, our_key, None, Network::Regtest).script_pubkey();
        let other_script =
            Address::p2tr(SECP256K1, other_key, None, Network::Regtest).script_pubkey();
        let tx = dummy_v3_tx(vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: other_script,
            },
        ]);
        assert!(first_output_paying_script(&tx, &our_script).is_none());
    }

    #[test]
    fn first_payout_picks_first_match_when_multiple_match() {
        // Defensive: if two outputs somehow pay our script, return the FIRST. The slash tx
        // shouldn't ever produce duplicate payouts (each watchtower has a unique
        // descriptor), but enforce the deterministic-first-match invariant.
        let our_key = xonly_from_seed(1);
        let our_script = Address::p2tr(SECP256K1, our_key, None, Network::Regtest).script_pubkey();
        let tx = dummy_v3_tx(vec![
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: our_script.clone(),
            }, // vout 0
            TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: our_script.clone(),
            }, // vout 1
        ]);
        let found = first_output_paying_script(&tx, &our_script).expect("should find first match");
        assert_eq!(found.vout, 0);
    }

    fn setup_btc_client(bitcoind: &Node) -> BitcoinClient {
        let cookie = bitcoind
            .params
            .get_cookie_values()
            .expect("cookie file should be readable")
            .expect("cookie file should contain credentials");
        let auth = Auth::UserPass(cookie.user, cookie.password);

        BitcoinClient::new(bitcoind.rpc_url(), auth, None, None, None)
            .expect("async bitcoin rpc client should initialize")
    }

    fn missing_txid() -> Txid {
        Txid::from_slice(&[7; 32]).expect("txid bytes should be valid")
    }

    #[tokio::test]
    async fn is_txid_onchain_returns_false_for_missing_and_true_for_mined_transactions() {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");

        let bitcoind = Node::with_conf("bitcoind", &conf).expect("bitcoind should start");
        let mining_address = bitcoind
            .client
            .new_address()
            .expect("wallet address should be generated");
        bitcoind
            .client
            .generate_to_address(101, &mining_address)
            .expect("coinbase outputs should mature");

        let recipient = bitcoind
            .client
            .new_address()
            .expect("recipient address should be generated");
        let mined_txid = bitcoind
            .client
            .send_to_address(&recipient, Amount::ONE_BTC)
            .expect("wallet transaction should be created")
            .txid()
            .expect("wallet transaction result should expose a txid");
        bitcoind
            .client
            .generate_to_address(1, &mining_address)
            .expect("transaction should be mined");

        let rpc_client = setup_btc_client(&bitcoind);
        assert!(
            !is_txid_onchain(&rpc_client, &missing_txid())
                .await
                .expect("unknown txids should be treated as missing")
        );

        assert!(
            is_txid_onchain(&rpc_client, &mined_txid)
                .await
                .expect("mined transactions should be found")
        );

        assert!(
            is_txid_onchain(&rpc_client, &mined_txid)
                .await
                .expect("duplicate lookups should remain stable")
        );
    }

    /// Tracks the source outpoint of a single spending transaction across its
    /// full lifecycle — locally signed (not broadcast), in mempool, and mined —
    /// and asserts both `is_outpoint_unspent` and the spending tx's
    /// confirmation count at each stage. Also covers the missing-outpoint case.
    #[tokio::test]
    async fn is_outpoint_unspent_tracks_spending_tx_lifecycle() {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");

        let bitcoind = Node::with_conf("bitcoind", &conf).expect("bitcoind should start");
        let mining_address = bitcoind
            .client
            .new_address()
            .expect("wallet address should be generated");
        bitcoind
            .client
            .generate_to_address(101, &mining_address)
            .expect("coinbase outputs should mature");

        let rpc_client = setup_btc_client(&bitcoind);

        // The matured coinbase output is the source outpoint we'll track.
        let first_block = rpc_client
            .get_block_at(1)
            .await
            .expect("first mined block should be retrievable");
        let coinbase_tx = first_block
            .coinbase()
            .expect("first mined block should contain a coinbase transaction");
        let source_outpoint = OutPoint {
            txid: coinbase_tx.compute_txid(),
            vout: 0,
        };

        // Outpoints whose txid does not exist on chain are reported as not unspent.
        let missing_outpoint = OutPoint {
            txid: missing_txid(),
            vout: 0,
        };
        assert!(
            !is_outpoint_unspent(&rpc_client, &missing_outpoint)
                .await
                .expect("rpc call should succeed for missing outpoint"),
            "missing outpoint should be reported as not unspent"
        );

        // Build a spending tx that sweeps the coinbase to a fresh wallet address
        // (minus a small fee). With only one matured UTXO available, this is the
        // only spend the wallet can produce.
        let recipient = bitcoind
            .client
            .new_address()
            .expect("recipient address should be generated");
        let inputs = [Input {
            txid: source_outpoint.txid,
            vout: u64::from(source_outpoint.vout),
            sequence: None,
        }];
        let outputs = [Output::new(
            recipient,
            Amount::from_sat(REGTEST_COINBASE_AMOUNT.to_sat() - 2_000),
        )];
        let unsigned_tx = bitcoind
            .client
            .create_raw_transaction(&inputs, &outputs)
            .expect("create raw tx")
            .transaction()
            .expect("decode unsigned tx");

        let signed = bitcoind
            .client
            .sign_raw_transaction_with_wallet(&unsigned_tx)
            .expect("wallet should sign the spending tx");
        assert!(
            signed.complete,
            "wallet should produce a complete signature"
        );
        let signed_tx: Transaction =
            deserialize_hex(&signed.hex).expect("signed tx hex should deserialize");
        let spending_txid = signed_tx.compute_txid();

        // STAGE 1: signed locally but not broadcast.
        // Source outpoint is still unspent. Spending tx is unknown to the node.
        assert!(
            is_outpoint_unspent(&rpc_client, &source_outpoint)
                .await
                .expect("rpc call must succeed"),
            "stage 1 (unbroadcast): source outpoint should still be unspent"
        );
        assert!(
            rpc_client
                .get_raw_transaction_verbosity_one(&spending_txid)
                .await
                .is_err(),
            "stage 1 (unbroadcast): spending tx should not be retrievable"
        );

        // STAGE 2: broadcast to mempool, not yet mined.
        // Source outpoint is reported as spent because we query gettxout with
        // include_mempool=true. Spending tx exists with no confirmations.
        bitcoind
            .client
            .send_raw_transaction(&signed_tx)
            .expect("broadcast spending tx");
        assert!(
            !is_outpoint_unspent(&rpc_client, &source_outpoint)
                .await
                .expect("rpc"),
            "stage 2 (mempool): source outpoint should be reported as spent"
        );
        let mempool_status = rpc_client
            .get_raw_transaction_verbosity_one(&spending_txid)
            .await
            .expect("spending tx should be retrievable from mempool");
        assert_eq!(
            mempool_status.confirmations, None,
            "stage 2 (mempool): spending tx should have no confirmations"
        );

        // STAGE 3: mined.
        // Source outpoint is consumed on chain. Spending tx has at least one
        // confirmation.
        bitcoind
            .client
            .generate_to_address(1, &mining_address)
            .expect("mine the spending tx");
        assert!(
            !is_outpoint_unspent(&rpc_client, &source_outpoint)
                .await
                .expect("rpc"),
            "stage 3 (mined): source outpoint should be reported as spent"
        );
        let mined_status = rpc_client
            .get_raw_transaction_verbosity_one(&spending_txid)
            .await
            .expect("mined spending tx should be retrievable");
        assert!(
            mined_status.confirmations.is_some_and(|c| c >= 1),
            "stage 3 (mined): spending tx should have ≥1 confirmation, got {:?}",
            mined_status.confirmations
        );
    }

    /// Drives the previous-backend gate through the outcomes that decide whether a persisted
    /// withdrawal-funding row may be discarded. Only unspent-at-a-foreign-script says
    /// "previous backend" (discard); unspent at the current backend's own script, spent in
    /// the mempool, spent on chain, and a mixed set all say "keep".
    #[tokio::test]
    async fn previous_backend_gate_discards_only_unspent_foreign_outpoints() {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");

        let bitcoind = Node::with_conf("bitcoind", &conf).expect("bitcoind should start");
        let mining_address = bitcoind
            .client
            .new_address()
            .expect("wallet address should be generated");
        bitcoind
            .client
            .generate_to_address(102, &mining_address)
            .expect("coinbase outputs should mature");

        let rpc_client = setup_btc_client(&bitcoind);

        // Two matured coinbase outputs stand in for a persisted funding row. Their script
        // belongs to the node wallet — a "previous backend" relative to any other script.
        let mut outpoints = Vec::new();
        let mut spks = Vec::new();
        for height in [1, 2] {
            let block = rpc_client
                .get_block_at(height)
                .await
                .expect("mined block should be retrievable");
            let coinbase_tx = block
                .coinbase()
                .expect("mined block should contain a coinbase transaction");
            outpoints.push(OutPoint {
                txid: coinbase_tx.compute_txid(),
                vout: 0,
            });
            spks.push(coinbase_tx.output[0].script_pubkey.clone());
        }
        let own_spk = spks[0].clone();
        let foreign_spk = Address::p2tr(
            SECP256K1,
            xonly_from_seed(3),
            None,
            bitcoin::Network::Regtest,
        )
        .script_pubkey();

        // All unspent at a script that is not the current backend's: the backend-switch
        // signature — the one outcome that may discard.
        assert!(
            outpoints_belong_to_previous_backend(&rpc_client, &outpoints, &foreign_spk)
                .await
                .expect("rpc should succeed"),
            "unspent outpoints at a foreign script should classify as previous-backend"
        );

        // Same outpoints, but the current backend claims that script: anomaly, keep.
        assert!(
            !outpoints_belong_to_previous_backend(&rpc_client, &outpoints, &own_spk)
                .await
                .expect("rpc should succeed"),
            "unspent outpoints at the current backend's script must not discard"
        );

        // Spend the first outpoint into the mempool (not mined): the gate must see the
        // mempool spend and keep the row — this is the own-WFT-pending window.
        let recipient = bitcoind
            .client
            .new_address()
            .expect("recipient address should be generated");
        let inputs = [Input {
            txid: outpoints[0].txid,
            vout: u64::from(outpoints[0].vout),
            sequence: None,
        }];
        let outputs = [Output::new(
            recipient,
            Amount::from_sat(REGTEST_COINBASE_AMOUNT.to_sat() - 2_000),
        )];
        let unsigned_tx = bitcoind
            .client
            .create_raw_transaction(&inputs, &outputs)
            .expect("create raw tx")
            .transaction()
            .expect("decode unsigned tx");
        let signed = bitcoind
            .client
            .sign_raw_transaction_with_wallet(&unsigned_tx)
            .expect("wallet should sign the spending tx");
        assert!(
            signed.complete,
            "wallet should produce a complete signature"
        );
        let signed_tx: Transaction =
            deserialize_hex(&signed.hex).expect("signed tx hex should deserialize");
        bitcoind
            .client
            .send_raw_transaction(&signed_tx)
            .expect("broadcast spending tx");

        // Spent-in-mempool alone → keep.
        assert!(
            !outpoints_belong_to_previous_backend(&rpc_client, &outpoints[..1], &foreign_spk)
                .await
                .expect("rpc should succeed"),
            "a mempool-spent outpoint must not classify as previous-backend"
        );
        // Mixed set (one spent, one unspent-foreign) → keep.
        assert!(
            !outpoints_belong_to_previous_backend(&rpc_client, &outpoints, &foreign_spk)
                .await
                .expect("rpc should succeed"),
            "a partially spent set must not classify as previous-backend"
        );

        // Mined spend → still keep.
        bitcoind
            .client
            .generate_to_address(1, &mining_address)
            .expect("mine the spending tx");
        assert!(
            !outpoints_belong_to_previous_backend(&rpc_client, &outpoints, &foreign_spk)
                .await
                .expect("rpc should succeed"),
            "a chain-spent outpoint must not classify as previous-backend"
        );
    }
}
