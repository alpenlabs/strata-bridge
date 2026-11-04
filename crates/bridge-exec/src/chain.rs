//! Shared Bitcoin chain helpers for executors.

use bitcoin::{
    Address, Amount, FeeRate, OutPoint, Psbt, Script, ScriptBuf, TapSighashType, Transaction,
    TxOut, Txid,
    secp256k1::SECP256K1,
    sighash::{Prevouts, SighashCache},
    taproot::ControlBlock,
    transaction::InputWeightPrediction,
};
use bitcoind_async_client::{Client as BitcoinClient, error::ClientError, traits::Reader};
use btc_tracker::{
    cpfp::{CpfpStrategy, DeadlineClass, FirstBump},
    event::TxStatus,
};
use operator_wallet::{FundingInput, Lease, LeaseOwner, OperatorWallet, WalletStore};
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_primitives::{cpfp::ChildSpend, scripts::taproot::create_key_spend_hash};
use strata_bridge_tx_graph::fee;
use tracing::{debug, error, info, warn};

use crate::{errors::ExecutorError, output_handles::OutputHandles};

/// How the publish path learns the exact fee that a parent pays.
///
/// The CPFP child pays the difference between what the parent already paid and what the
/// package target asks for, so a wrong value here makes the child overpay or underpay.
#[derive(Debug, Clone, Copy)]
pub(crate) enum ParentFee {
    /// The fee is the value of the prevouts of the published transaction minus its outputs. The
    /// transaction itself cannot be wrong about that.
    ///
    /// The lookup needs the node to know each prevout transaction, which takes `txindex=1` for
    /// a confirmed one.
    ///
    /// A presigned parent, or one that an earlier process funded, states this. Its fee was fixed
    /// before the market was known, so its first bump runs at the publish.
    FromPrevouts,
    /// The caller knows the fee that the parent pays, because it funded the parent at the market
    /// rate just now. The first bump of such a parent waits for a trigger, because a child at the
    /// publish would pay the premium of the ladder for nothing.
    Exact(Amount),
}

impl ParentFee {
    /// When the first bump of a parent with this fee runs. See the variants.
    const fn first_bump(self) -> FirstBump {
        match self {
            Self::FromPrevouts => FirstBump::AtPublish,
            Self::Exact(_) => FirstBump::AtTrigger,
        }
    }
}

impl ParentFee {
    /// Resolves to the fee that `tx` pays.
    async fn resolve(
        self,
        bitcoind_rpc_client: &BitcoinClient,
        tx: &Transaction,
    ) -> Result<Amount, ClientError> {
        match self {
            Self::FromPrevouts => {
                let prevouts = fetch_prevouts(bitcoind_rpc_client, tx).await?;
                exact_fee_from_prevouts(&prevouts, tx).ok_or_else(|| {
                    ClientError::MalformedResponse(format!(
                        "the prevouts of {} do not cover its outputs",
                        tx.compute_txid()
                    ))
                })
            }
            Self::Exact(fee) => Ok(fee),
        }
    }
}

/// Reads the outputs that `tx` spends, in input order.
pub(crate) async fn fetch_prevouts(
    bitcoind_rpc_client: &BitcoinClient,
    tx: &Transaction,
) -> Result<Vec<TxOut>, ClientError> {
    let mut prevouts = Vec::with_capacity(tx.input.len());
    for input in &tx.input {
        let outpoint = input.previous_output;
        let prev_tx = bitcoind_rpc_client
            .get_raw_transaction_verbosity_zero(&outpoint.txid)
            .await?
            .0;
        let prevout = prev_tx.output.get(outpoint.vout as usize).ok_or_else(|| {
            ClientError::MalformedResponse(format!("{outpoint} is out of bounds"))
        })?;
        prevouts.push(prevout.clone());
    }
    Ok(prevouts)
}

/// Validates the caller-named anchor and returns the child spend for it.
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
fn checked_anchor_spend(
    tx: &Transaction,
    anchor_vout: u32,
    anchor_key: bitcoin::XOnlyPublicKey,
    signing_key: bitcoin::XOnlyPublicKey,
    network: bitcoin::Network,
    label: &str,
) -> Option<ChildSpend> {
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
    Some(ChildSpend::keyed_anchor(OutPoint {
        txid,
        vout: anchor_vout,
    }))
}

/// Returns the first output of `tx` that pays `expected_script`.
///
/// [`CpfpKind::InferGeneralPayout`] reads the general-wallet receive script here: the BIP86-tweaked
/// P2TR of secret-service custody, or the vault P2WPKH of Fireblocks. Both pay change to this
/// script.
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
fn exact_fee_from_prevouts(prevouts: &[TxOut], tx: &Transaction) -> Option<Amount> {
    let inputs_sum = prevouts
        .iter()
        .try_fold(Amount::ZERO, |acc, o| acc.checked_add(o.value))?;
    let outputs_sum = tx
        .output
        .iter()
        .try_fold(Amount::ZERO, |acc, o| acc.checked_add(o.value))?;
    inputs_sum.checked_sub(outputs_sum)
}

/// Returns the fee of `tx` at `fee_rate`, where one input is empty and takes a witness that
/// `wallet_input` predicts. Every other input must carry its final witness.
///
/// The prediction counts the empty input's script length and witness count, which `tx` already
/// holds, and it takes the largest witness of its kind. So the fee lands at most that slack above
/// the exact value, and never below it.
pub(crate) fn funded_tx_fee(
    tx: &Transaction,
    wallet_input: InputWeightPrediction,
    fee_rate: FeeRate,
) -> Option<Amount> {
    fee_rate.fee_wu(tx.weight() + wallet_input.weight())
}

/// The output that each input of `psbt` spends, in input order.
pub(crate) fn psbt_prevouts(psbt: &Psbt) -> Vec<TxOut> {
    psbt.inputs
        .iter()
        .map(|input| {
            input
                .witness_utxo
                .clone()
                .expect("a wallet-funded PSBT carries witness_utxo on every input")
        })
        .collect()
}

/// Signs the general-wallet inputs of `tx` at `input_indices` and leaves every other input as it
/// is. `prevouts[i]` is the output spent by `tx.input[i]`.
///
/// The wallet's signer signs the inputs that it holds keys for. Secret-service signs the rest as
/// Taproot key-path spends. A sighash commits to no witness, so the other inputs can be signed or
/// not. The caller holds no wallet guard here, and this function holds one only to take the
/// signer, so a wait on an external signer stalls no other duty. A caller that keeps a lease on the
/// inputs drops it when this fails, which returns them.
pub(crate) async fn sign_general_inputs(
    output_handles: &OutputHandles,
    tx: &Transaction,
    input_indices: &[usize],
    prevouts: &[TxOut],
) -> Result<Transaction, ExecutorError> {
    let signer = output_handles.wallet.read().await.general_signer();
    let signer_witnesses = signer
        .sign_owned_inputs(tx, input_indices, prevouts)
        .await
        .map_err(|e| ExecutorError::WalletErr(format!("wallet signing failed: {e}")))?;

    let prevouts = Prevouts::All(prevouts);
    let mut sighash_cache = SighashCache::new(tx);
    let s2_signer = output_handles.s2_client.general_wallet_signer();

    let mut signed_tx = tx.clone();
    for (&input_index, signer_witness) in input_indices.iter().zip(signer_witnesses) {
        if let Some(witness) = signer_witness {
            signed_tx.input[input_index].witness = witness;
            continue;
        }
        let sighash = create_key_spend_hash(
            &mut sighash_cache,
            prevouts.clone(),
            TapSighashType::Default,
            input_index,
        )
        .map_err(|e| ExecutorError::WalletErr(format!("key spend hash: {e}")))?;
        let signature = s2_signer
            .sign(sighash.as_ref(), None)
            .await
            .map_err(ExecutorError::SecretServiceErr)?;
        signed_tx.input[input_index]
            .witness
            .push(signature.serialize());
    }

    Ok(signed_tx)
}

/// Returns the confirmation count of a transaction that the node knows, or `None` for an unknown
/// transaction. A mempool transaction has zero. A confirmed transaction stays known after its
/// outputs are spent, which takes `txindex=1`.
pub(crate) async fn tx_confirmations(
    bitcoind_rpc_client: &BitcoinClient,
    txid: &Txid,
) -> Result<Option<u64>, ClientError> {
    debug!(%txid, "reading tx confirmations");
    match bitcoind_rpc_client
        .get_raw_transaction_verbosity_one(txid)
        .await
    {
        Ok(tx) => Ok(Some(tx.confirmations.unwrap_or(0))),
        Err(e) if e.is_tx_not_found() => Ok(None),
        Err(e) => {
            warn!(%txid, ?e, "could not read tx confirmations");
            Err(e)
        }
    }
}

/// Returns whether `txid` is in the mempool or in a block of the active chain.
///
/// `txindex` keeps a transaction of a block that a reorg removed. The node then reports it with a
/// block hash and zero confirmations, and such a transaction is not on chain.
pub(crate) async fn is_txid_onchain(
    bitcoind_rpc_client: &BitcoinClient,
    txid: &Txid,
) -> Result<bool, ClientError> {
    debug!(%txid, "reading whether the transaction is on chain");
    match bitcoind_rpc_client
        .get_raw_transaction_verbosity_one(txid)
        .await
    {
        Ok(tx) => Ok(tx.block_hash.is_none() || tx.confirmations.unwrap_or(0) > 0),
        Err(e) if e.is_tx_not_found() => Ok(false),
        Err(e) => {
            warn!(%txid, ?e, "could not read the transaction");
            Err(e)
        }
    }
}

/// Returns the mempool transaction that spends `outpoint`, if any. A spend that confirmed is
/// not in the mempool and reads as `None`.
pub(crate) async fn mempool_spender(
    bitcoind_rpc_client: &BitcoinClient,
    outpoint: OutPoint,
) -> Result<Option<Txid>, ClientError> {
    /// One entry of a `gettxspendingprevout` response.
    #[derive(Debug, serde::Deserialize)]
    struct PrevoutSpend {
        /// Absent when nothing spends the outpoint.
        #[serde(rename = "spendingtxid")]
        spending_txid: Option<Txid>,
    }

    // The typed surface of the client does not cover `gettxspendingprevout`, so call it raw.
    let query = serde_json::json!([{ "txid": outpoint.txid.to_string(), "vout": outpoint.vout }]);
    let spends: Vec<PrevoutSpend> = bitcoind_rpc_client
        .call_raw("gettxspendingprevout", &[query])
        .await?;
    Ok(spends.into_iter().find_map(|spend| spend.spending_txid))
}

/// Returns the unspent output at `outpoint`, on chain or in the mempool.
///
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
            warn!(%outpoint, ?e, "could not read outpoint");
            Err(e)
        }
    }
}

/// Hint that lets the caller of [`publish_signed_transaction`] say how a parent takes a CPFP
/// child. Every variant that takes a child states how to learn the fee of the parent and which
/// [`DeadlineClass`] the parent is in.
///
/// - [`Self::AnchorAt`]: the parent carries an operator-keyed Taproot anchor at a vout that the
///   caller knows statically (each tx type exports its anchor vout as a constant). Applies to
///   claim/stake/unstaking_intent/counterproof/counterproof_ack and any other tx with a
///   `KeyedAnchor` connector. The publish helper checks the named output against the expected
///   anchor script and value before it enables CPFP.
/// - [`Self::PayoutCombined`]: no keyed anchor. The CPFP child spends the operator-owned output at
///   a vout that the caller knows statically. Applies to cooperative_payout, uncontested_payout,
///   contested_payout, unstaking, counterproof_nack and the change output of the bridge proof.
/// - [`Self::InferGeneralPayout`]: the child spends the first output paying the operator's
///   general-wallet script. Applies to txs whose operator-owned output has no fixed vout:
///   withdrawal fulfillment and stake funding, where the change output can be absent, and slash,
///   where the vout depends on the position of this watchtower. A scan that finds no such output
///   publishes without CPFP. On slash this happens when the covenant `payout_descriptor` of this
///   operator does not pay the general-wallet script.
/// - [`Self::MultiAnchor`]: the child spends a script-path leaf of a multi-key anchor. Applies to
///   contest, bridge proof timeout and sweep.
/// - [`Self::None`]: broadcast as-is. Use only when the tx has no CPFP hook, such as the deposit.
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
        /// How to learn the fee of the parent.
        parent_fee: ParentFee,
        /// Whether a protocol timelock races this parent.
        deadline: DeadlineClass,
    },
    /// Build the child by spending the operator-owned output of the parent at this vout.
    PayoutCombined {
        /// Index of the output that the child spends.
        payout_vout: u32,
        /// How to learn the fee of the parent.
        parent_fee: ParentFee,
        /// Whether a protocol timelock races this parent.
        deadline: DeadlineClass,
    },
    /// Look for the first output paying the operator's general-wallet script and use it as
    /// the CPFP payout. Falls back to no-CPFP if no such output exists (e.g. the planner added
    /// no change output).
    InferGeneralPayout {
        /// How to learn the fee of the parent.
        parent_fee: ParentFee,
        /// Whether a protocol timelock races this parent.
        deadline: DeadlineClass,
    },
    /// Bump a multi-leaf (`MultiAnchor`) anchor script-path, satisfying the leaf that this
    /// operator holds. The leaf depends on the key list that built the anchor and on the position
    /// of this operator in it, so the caller supplies the full spend data.
    MultiAnchor {
        /// Index of the anchor output on the parent.
        anchor_vout: u32,
        /// The leaf script this operator may satisfy.
        leaf_script: ScriptBuf,
        /// Control block proving the leaf's membership in the anchor's tree.
        control_block: ControlBlock,
        /// How to learn the fee of the parent.
        parent_fee: ParentFee,
        /// Whether a protocol timelock races this parent.
        deadline: DeadlineClass,
    },
    /// No CPFP — broadcast as-is.
    None,
}

/// Publishes a signed transaction and waits for its burial. See
/// [`publish_signed_transaction_until`].
pub(crate) async fn publish_signed_transaction(
    output_handles: &OutputHandles,
    signed_tx: &Transaction,
    label: &str,
    cpfp: CpfpKind,
) -> Result<(), ExecutorError> {
    publish_signed_transaction_until(output_handles, signed_tx, label, cpfp, TxStatus::is_buried)
        .await
}

/// Publishes a signed transaction and waits until its status meets `condition`. The `cpfp`
/// parameter drives strategy selection — see [`CpfpKind`]. A parent with a CPFP path keeps its
/// bumps after `condition` holds, until its burial.
///
/// A caller that knows the fee states [`ParentFee::Exact`], for example with `Psbt::fee()`, which
/// resolves because the funding planner sets `witness_utxo` on every input. Any other caller
/// states [`ParentFee::FromPrevouts`].
///
/// A failed fee lookup does not block the publish: the transaction goes out without a CPFP path,
/// and the next trigger of the duty reads the fee again.
pub(crate) async fn publish_signed_transaction_until(
    output_handles: &OutputHandles,
    signed_tx: &Transaction,
    label: &str,
    cpfp: CpfpKind,
    condition: impl Fn(&TxStatus) -> bool + Send + 'static,
) -> Result<(), ExecutorError> {
    let txid = signed_tx.compute_txid();
    let child = match cpfp {
        CpfpKind::AnchorAt {
            anchor_vout,
            anchor_key,
            parent_fee,
            deadline,
        } => checked_anchor_spend(
            signed_tx,
            anchor_vout,
            anchor_key,
            output_handles.operator_musig2_pubkey,
            output_handles.network,
            label,
        )
        .map(|spend| (spend, parent_fee, deadline)),
        CpfpKind::PayoutCombined {
            payout_vout,
            parent_fee,
            deadline,
        } => Some((
            ChildSpend::owned_output(OutPoint {
                txid,
                vout: payout_vout,
            }),
            parent_fee,
            deadline,
        )),
        CpfpKind::InferGeneralPayout {
            parent_fee,
            deadline,
        } => {
            let payout =
                first_output_paying_script(signed_tx, &output_handles.general_script_pubkey);
            if payout.is_none() {
                warn!(
                    %txid,
                    %label,
                    "no output pays the operator's general-wallet script; publishing without CPFP"
                );
            }
            payout.map(|outpoint| (ChildSpend::owned_output(outpoint), parent_fee, deadline))
        }
        CpfpKind::MultiAnchor {
            anchor_vout,
            leaf_script,
            control_block,
            parent_fee,
            deadline,
        } => Some((
            ChildSpend::multi_anchor(
                OutPoint {
                    txid,
                    vout: anchor_vout,
                },
                leaf_script,
                control_block,
            ),
            parent_fee,
            deadline,
        )),
        CpfpKind::None => None,
    };
    let strategy = resolve_strategy(child, &output_handles.bitcoind_rpc_client, signed_tx).await;

    let cpfp_enabled = strategy.is_some();
    info!(%txid, %label, cpfp_enabled, "publishing transaction");
    let tx_driver = &output_handles.tx_driver;
    let drive_result = match strategy {
        Some(strategy) => {
            tx_driver
                .drive_with_cpfp(signed_tx.clone(), strategy, condition)
                .await
        }
        None => tx_driver.drive(signed_tx.clone(), condition).await,
    };
    drive_result.map_err(|e| {
        warn!(%txid, %label, ?e, "failed to publish transaction");
        ExecutorError::TxDriverErr(e)
    })?;

    info!(%txid, %label, "transaction reached target status");
    Ok(())
}

/// Returns the mempool transaction that spends `outpoints` and pays `recipients` as its first
/// outputs, or `None` when no mempool transaction spends them.
///
/// A duty that funded a transaction from stored inputs reads this on a retry: the transaction an
/// earlier process broadcast spends those inputs, and only a re-drive of it keeps its bump path.
/// Only the first stored outpoint is read, because one transaction spends them all. A spender
/// that does not pay `recipients` is a conflict that the duty cannot resolve, and it reads as
/// `None` so that the rebuild reports the spent input.
pub(crate) async fn mempool_spender_paying(
    bitcoind_rpc_client: &BitcoinClient,
    outpoints: &[OutPoint],
    recipients: &[TxOut],
) -> Result<Option<Transaction>, ClientError> {
    let Some(first) = outpoints.first() else {
        return Ok(None);
    };
    let Some(spender) = mempool_spender(bitcoind_rpc_client, *first).await? else {
        return Ok(None);
    };
    let tx = bitcoind_rpc_client
        .get_raw_transaction_verbosity_zero(&spender)
        .await?
        .0;
    let pays_recipients = tx.output.starts_with(recipients);
    if !pays_recipients {
        warn!(%spender, "a mempool transaction spends the stored inputs and pays other outputs");
    }
    Ok(pays_recipients.then_some(tx))
}

/// Reads the fee of `tx` for the `child` that the publish path resolved. A failed read returns
/// `None`, which publishes without CPFP, and the next trigger reads again.
async fn resolve_strategy(
    child: Option<(ChildSpend, ParentFee, DeadlineClass)>,
    bitcoind_rpc_client: &BitcoinClient,
    tx: &Transaction,
) -> Option<CpfpStrategy> {
    let (spend, parent_fee, deadline) = child?;
    let first_bump = parent_fee.first_bump();
    match parent_fee.resolve(bitcoind_rpc_client, tx).await {
        Ok(parent_fee) => Some(CpfpStrategy {
            spend,
            parent_fee,
            deadline,
            first_bump,
        }),
        Err(err) => {
            warn!(txid = %tx.compute_txid(), %err, "could not read the parent fee; publishing without CPFP");
            None
        }
    }
}

/// Publishes a transaction whose wallet inputs `lease` holds.
///
/// Success commits the lease: the transaction spends the inputs, and the lease stays in place
/// until a sync observes that. A failure releases the lease through [`release_after_sync`]: a
/// failed publish can still have reached a mempool (a package whose submission timed out), so the
/// inputs return to the pool only against a fresh view, and they stay held when that view cannot
/// be read.
pub(crate) async fn publish_leased_transaction(
    output_handles: &OutputHandles,
    signed_tx: &Transaction,
    label: &str,
    cpfp: CpfpKind,
    lease: Lease,
) -> Result<(), ExecutorError> {
    let result = publish_signed_transaction(output_handles, signed_tx, label, cpfp).await;
    match result {
        Ok(()) => lease.commit(),
        Err(_) => {
            let mut wallet = output_handles.wallet.write().await;
            if let Err(e) = release_after_sync(&mut wallet, lease).await {
                warn!(%label, ?e, "wallet sync failed after a failed publish; the inputs stay held");
            }
        }
    }
    result
}

/// Syncs, then gives up `lease` on the inputs of a transaction that can be on the network.
///
/// A successful sync makes the wallet view authoritative: the wallet hides the inputs of a
/// broadcast transaction, and dropping the lease returns only the inputs that no transaction
/// spends. A failed sync leaves the view stale, and a release against stale data hands a live
/// transaction's inputs to the next duty, which then broadcasts a conflicting spend. The lease
/// commits in that case. An input of a transaction that never reached the network then stays out
/// of selection until a restart, so this logs the outpoints at error, and the operator restarts
/// when funding runs out.
pub(crate) async fn release_after_sync<P: WalletStore>(
    wallet: &mut OperatorWallet<P>,
    lease: Lease,
) -> Result<(), operator_wallet::Error> {
    if let Err(e) = wallet.sync().await {
        error!(inputs = ?lease.outpoints(), "wallet sync failed; holding the inputs");
        lease.commit();
        return Err(e);
    }
    Ok(())
}

/// One general-wallet input that funds a transaction with a connector input, and the change that
/// it leaves.
#[derive(Debug)]
pub(crate) struct ConnectorFunding {
    /// The selected input.
    pub(crate) input: FundingInput,
    /// The lease on [`Self::input`].
    pub(crate) lease: Lease,
    /// The change output, always above dust.
    pub(crate) change: TxOut,
    /// The fee that the funded transaction pays.
    pub(crate) fee: Amount,
}

/// Selects and leases a confirmed general-wallet UTXO that, with `connector_value`, pays the fee
/// of `template` at `fee_rate` and leaves non-dust change.
///
/// One wallet input funds the transaction, because the callers hand-build a fixed shape. A wallet
/// with enough total value in smaller outputs fails here, and the log states that total.
///
/// `template` is the funded transaction as [`funded_tx_fee`] reads it. The selection reads
/// confirmed outputs only: these transactions are v3, and TRUC rejects a v3 transaction on an
/// unconfirmed non-v3 parent.
pub(crate) fn select_connector_funding<P: WalletStore>(
    wallet: &mut OperatorWallet<P>,
    owner: LeaseOwner,
    template: &Transaction,
    connector_value: Amount,
    fee_rate: FeeRate,
) -> Result<ConnectorFunding, ExecutorError> {
    let overflow = || ExecutorError::WalletErr("connector funding amount overflow".into());
    let change_script = wallet.general().script_pubkey();
    let fee = funded_tx_fee(
        template,
        wallet.general_signer().input_prediction(),
        fee_rate,
    )
    .ok_or_else(overflow)?;
    let min_funding = fee
        .checked_add(change_script.minimal_non_dust())
        .ok_or_else(overflow)?
        .checked_sub(connector_value)
        .unwrap_or(Amount::ZERO);

    let (input, lease) = wallet
        .select_general_utxo(owner, min_funding)
        .ok_or_else(|| {
            let confirmed_total: Amount = wallet
                .general()
                .list_utxos()
                .iter()
                .filter(|utxo| utxo.confirmations > 0)
                .map(|utxo| utxo.amount)
                .sum();
            error!(
                %fee,
                %fee_rate,
                %min_funding,
                %confirmed_total,
                ?owner,
                "no single general wallet UTXO covers this fee"
            );
            ExecutorError::WalletErr(format!(
                "no general wallet UTXO of at least {min_funding} funds {owner:?}"
            ))
        })?;
    let change_value = connector_value
        .checked_add(input.txout.value)
        .and_then(|inputs| inputs.checked_sub(fee))
        .ok_or_else(overflow)?;
    info!(funding = %input.outpoint, %fee, %fee_rate, ?owner, "leased general wallet funding");
    Ok(ConnectorFunding {
        input,
        lease,
        change: TxOut {
            value: change_value,
            script_pubkey: change_script,
        },
        fee,
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Address, Amount, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Txid, absolute,
        consensus::encode::deserialize_hex,
        hashes::Hash,
        key::Secp256k1,
        secp256k1::{SECP256K1, SecretKey},
        transaction::Version,
    };
    use bitcoind_async_client::{Auth, Client as BitcoinClient, traits::Reader};
    use btc_tracker::cpfp::DeadlineClass;
    use corepc_node::{Conf, Input, Node, Output};
    use strata_bridge_primitives::cpfp::ChildSpend;
    use strata_bridge_tx_graph::fee;

    use super::{
        ParentFee, checked_anchor_spend, first_output_paying_script, is_outpoint_unspent,
        is_txid_onchain, mempool_spender_paying, resolve_strategy,
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

    /// A parent whose prevout the node cannot find has no known fee, so the publish path gets no
    /// strategy and publishes without CPFP.
    #[tokio::test]
    async fn an_unknown_prevout_publishes_without_cpfp() {
        let bitcoind =
            Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind should start");
        let client = setup_btc_client(&bitcoind);
        let mut parent = dummy_v3_tx(vec![]);
        parent.input.push(TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([9; 32]), 0),
            ..Default::default()
        });
        let spend = ChildSpend::owned_output(OutPoint::new(parent.compute_txid(), 0));
        let child = Some((spend, ParentFee::FromPrevouts, DeadlineClass::NoDeadline));

        assert!(resolve_strategy(child, &client, &parent).await.is_none());
        assert!(
            resolve_strategy(None, &client, &parent).await.is_none(),
            "a parent with no child reads no fee"
        );
    }

    /// The spender of stored inputs is this duty's transaction only when it pays the recipients.
    /// A reorg that returns a confirmed spender to the mempool makes it readable again.
    #[tokio::test]
    async fn mempool_spender_paying_finds_the_transaction_that_a_reorg_returns() {
        let bitcoind =
            Node::with_conf("bitcoind", &Conf::default()).expect("bitcoind should start");
        let client = setup_btc_client(&bitcoind);
        let miner = bitcoind.client.new_address().unwrap();
        bitcoind.client.generate_to_address(101, &miner).unwrap();

        let recipient = bitcoind.client.new_address().unwrap();
        let txid = bitcoind
            .client
            .send_to_address(&recipient, Amount::ONE_BTC)
            .unwrap()
            .txid()
            .unwrap();
        let tx = client
            .get_raw_transaction_verbosity_zero(&txid)
            .await
            .unwrap()
            .0;
        let inputs: Vec<OutPoint> = tx.input.iter().map(|input| input.previous_output).collect();
        let other = vec![TxOut {
            value: Amount::ONE_SAT,
            script_pubkey: ScriptBuf::new(),
        }];

        assert_eq!(
            mempool_spender_paying(&client, &inputs, &tx.output)
                .await
                .unwrap(),
            Some(tx.clone())
        );
        assert_eq!(
            mempool_spender_paying(&client, &inputs, &other)
                .await
                .unwrap(),
            None,
            "a spender that pays other outputs is not this transaction"
        );
        assert_eq!(
            mempool_spender_paying(&client, &[], &tx.output)
                .await
                .unwrap(),
            None,
            "no stored inputs, no spender"
        );

        bitcoind.client.generate_to_address(1, &miner).unwrap();
        assert_eq!(
            mempool_spender_paying(&client, &inputs, &tx.output)
                .await
                .unwrap(),
            None,
            "a confirmed spend is not in the mempool"
        );

        let stale: String = bitcoind.client.call("getbestblockhash", &[]).unwrap();
        let _: serde_json::Value = bitcoind
            .client
            .call("invalidateblock", &[serde_json::Value::String(stale)])
            .unwrap();
        assert_eq!(
            mempool_spender_paying(&client, &inputs, &tx.output)
                .await
                .unwrap(),
            Some(tx),
            "the reorg returns the spend to the mempool"
        );
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

        // Correct vout resolves to the spend.
        let spend = checked_anchor_spend(&tx, 1, anchor_key, anchor_key, network, "t")
            .expect("the named anchor must resolve");
        assert_eq!(spend.outpoint().vout, 1);

        // An anchor above the dust value (counterproof-ACK shape) also resolves.
        let ack_tx = dummy_v3_tx(vec![TxOut {
            value: dust * 2,
            script_pubkey: anchor_script,
        }]);
        assert!(checked_anchor_spend(&ack_tx, 0, anchor_key, anchor_key, network, "t").is_some());

        // A vout that names a non-anchor output is rejected.
        assert!(checked_anchor_spend(&tx, 0, anchor_key, anchor_key, network, "t").is_none());
        // A vout past the outputs is rejected.
        assert!(checked_anchor_spend(&tx, 9, anchor_key, anchor_key, network, "t").is_none());
        // A value below dust is rejected even on the right script.
        let low = dummy_v3_tx(vec![TxOut {
            value: dust - Amount::from_sat(1),
            script_pubkey: Address::p2tr(SECP256K1, anchor_key, None, network).script_pubkey(),
        }]);
        assert!(checked_anchor_spend(&low, 0, anchor_key, anchor_key, network, "t").is_none());

        // An anchor keyed to a key this operator cannot sign with disables the bump. A child
        // of that anchor carries a signature that no mempool accepts.
        assert!(
            checked_anchor_spend(&tx, 1, anchor_key, other_key, network, "t").is_none(),
            "an anchor key that this operator cannot sign with must disable the bump"
        );
    }

    #[test]
    fn first_output_paying_script_finds_the_match() {
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

    /// `txindex` keeps a transaction of a block that a reorg removed. A fee bump replaces it in
    /// the mempool, so the stale block is the only place that holds it, and it is not on chain.
    #[tokio::test]
    async fn is_txid_onchain_ignores_a_transaction_in_a_stale_block() {
        let mut conf = Conf::default();
        conf.args.push("-txindex=1");
        let bitcoind = Node::with_conf("bitcoind", &conf).expect("bitcoind should start");
        let mining_address = bitcoind.client.new_address().expect("mining address");
        bitcoind
            .client
            .generate_to_address(101, &mining_address)
            .expect("coinbase outputs should mature");
        let recipient = bitcoind.client.new_address().expect("recipient address");
        let original = bitcoind
            .client
            .send_to_address(&recipient, Amount::ONE_BTC)
            .expect("transaction should be sent")
            .txid()
            .expect("txid");
        bitcoind
            .client
            .generate_to_address(1, &mining_address)
            .expect("mine the original");

        let stale: String = bitcoind
            .client
            .call("getbestblockhash", &[])
            .expect("best block hash");
        let _: serde_json::Value = bitcoind
            .client
            .call("invalidateblock", &[serde_json::Value::String(stale)])
            .expect("invalidate the block");
        let bumped: serde_json::Value = bitcoind
            .client
            .call(
                "bumpfee",
                &[serde_json::Value::String(original.to_string())],
            )
            .expect("the original is back in the mempool and bumps");
        let replacement: Txid = bumped["txid"]
            .as_str()
            .expect("bumpfee reports the new txid")
            .parse()
            .expect("valid txid");
        bitcoind
            .client
            .generate_to_address(1, &mining_address)
            .expect("mine the replacement");

        let rpc_client = setup_btc_client(&bitcoind);
        assert!(
            !is_txid_onchain(&rpc_client, &original)
                .await
                .expect("a stale entry reads"),
            "a transaction that only a stale block holds is not on chain"
        );
        assert!(
            is_txid_onchain(&rpc_client, &replacement)
                .await
                .expect("the replacement reads")
        );
    }

    /// The fee of a parent that the caller did not fund comes from the outputs it spends. The
    /// lookup keeps working once the parent spends them, because a retried publish reads a
    /// parent that is already in the mempool or in a block.
    #[tokio::test]
    async fn parent_fee_resolves_from_prevouts_before_and_after_the_spend() {
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

        let coinbase_tx = rpc_client
            .get_block_at(1)
            .await
            .expect("first mined block should be retrievable")
            .coinbase()
            .expect("first mined block should contain a coinbase transaction")
            .clone();
        let recipient = bitcoind
            .client
            .new_address()
            .expect("recipient address should be generated");
        let fee = Amount::from_sat(2_000);
        let unsigned_tx = bitcoind
            .client
            .create_raw_transaction(
                &[Input {
                    txid: coinbase_tx.compute_txid(),
                    vout: 0,
                    sequence: None,
                }],
                &[Output::new(recipient, REGTEST_COINBASE_AMOUNT - fee)],
            )
            .expect("create raw tx")
            .transaction()
            .expect("decode unsigned tx");
        let signed = bitcoind
            .client
            .sign_raw_transaction_with_wallet(&unsigned_tx)
            .expect("wallet should sign the spending tx");
        let parent: Transaction =
            deserialize_hex(&signed.hex).expect("signed tx hex should deserialize");

        assert_eq!(
            ParentFee::FromPrevouts
                .resolve(&rpc_client, &parent)
                .await
                .expect("the prevout is confirmed"),
            fee
        );

        bitcoind
            .client
            .send_raw_transaction(&parent)
            .expect("broadcast the parent");
        bitcoind
            .client
            .generate_to_address(1, &mining_address)
            .expect("mine the parent");

        assert_eq!(
            ParentFee::FromPrevouts
                .resolve(&rpc_client, &parent)
                .await
                .expect("the prevout stays retrievable after the spend"),
            fee
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
}
