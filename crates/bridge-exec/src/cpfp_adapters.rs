//! Bridge-side implementations of the [`btc_tracker::cpfp`] traits.
//!
//! `btc-tracker` defines [`CpfpWallet`], [`CpfpFeeSource`], and [`CpfpMempool`] as
//! abstract interfaces so the crate stays at the bottom of the dependency graph. The concrete
//! adapters that wire those traits to the bridge's actual wallet, fee source, and Bitcoin Core
//! client live here.

use std::sync::Arc;

use bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, ScriptBuf, Transaction, XOnlyPublicKey,
    secp256k1::{Message, SECP256K1, schnorr::Signature},
    taproot::{ControlBlock, LeafVersion},
};
use bitcoind_async_client::{Client as BitcoinClient, traits::Reader};
use btc_tracker::{
    cpfp::{
        AnchorSpendState, CpfpFeeSource, CpfpMempool, CpfpStrategy, CpfpWallet, InputSignFut,
        InputSigner, WalletFundedPsbt,
    },
    submitpackage::{self, SubmitPackageError, SubmitPackageSummary},
};
use operator_wallet::{AnchorInfo, GeneralWallet, OperatorWallet};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_connectors::{Connector, prelude::MultiAnchor};
use strata_bridge_tx_graph::fee;
use tokio::sync::RwLock;
use tracing::warn;

/// Wraps the bridge's `Arc<RwLock<OperatorWallet<G>>>` and implements [`CpfpWallet`] over it.
///
/// Both [`CpfpStrategy`] variants funnel through
/// [`OperatorWallet::build_cpfp_child`](operator_wallet::OperatorWallet::build_cpfp_child) with the
/// foreign-UTXO machinery — the difference between them is just which output on the parent
/// the child consumes:
/// - [`CpfpStrategy::AnchorBearing`]: a 330-sat keyed-Taproot anchor at `anchor_vout`, internal key
///   = the operator's musig2 pubkey (the "btc key" from the operator table).
/// - [`CpfpStrategy::ParentTxCombined`]: the operator's payout output at `payout_outpoint.vout`,
///   internal key = the operator's general-wallet pubkey (the bridge assumes the operator's
///   covenant `payout_descriptor` resolves to the general-wallet P2TR — if not, signing fails
///   downstream and the bump is skipped + retried).
///
/// Treating the payout as a foreign UTXO (rather than asking BDK to track it in the wallet's
/// UTXO set) is essential: the parent has NOT been broadcast at the time we build the child
/// (we submit `[parent, child]` as a v3 1P1C package), so BDK has no knowledge of the
/// payout outpoint. `add_foreign_utxo` accepts it with a caller-provided `witness_utxo`.
#[derive(Debug)]
pub struct OperatorWalletCpfpAdapter<G: GeneralWallet + std::fmt::Debug + 'static> {
    wallet: Arc<RwLock<OperatorWallet<G>>>,
    /// Operator's general-wallet pubkey. Used as the foreign-UTXO `tap_internal_key` when
    /// CPFPing a [`CpfpStrategy::ParentTxCombined`] parent — every payout output across
    /// cooperative_payout / uncontested_payout / contested_payout / unstaking goes to the
    /// operator's payout descriptor, which the bridge expects to be the general-wallet P2TR.
    operator_general_pubkey: XOnlyPublicKey,
}

impl<G: GeneralWallet + std::fmt::Debug + 'static> OperatorWalletCpfpAdapter<G> {
    /// Constructs a new adapter wrapping the shared wallet handle. `operator_general_pubkey`
    /// is the operator's general-wallet x-only pubkey (typically fetched once at
    /// orchestrator startup via `s2_client.general_wallet_signer().pubkey()`).
    pub const fn new(
        wallet: Arc<RwLock<OperatorWallet<G>>>,
        operator_general_pubkey: XOnlyPublicKey,
    ) -> Self {
        Self {
            wallet,
            operator_general_pubkey,
        }
    }
}

impl<G: GeneralWallet + std::fmt::Debug + 'static> CpfpWallet for OperatorWalletCpfpAdapter<G> {
    fn build_cpfp_child(
        &self,
        parent: &Transaction,
        strategy: CpfpStrategy,
        target_pkg_fee_rate: FeeRate,
        replacing: Option<&[OutPoint]>,
    ) -> impl std::future::Future<Output = Result<WalletFundedPsbt, String>> + Send {
        // Clone what we need into the future so the returned future owns its captures.
        let wallet_arc = self.wallet.clone();
        let parent_owned = parent.clone();
        let replacing_owned: Option<Vec<OutPoint>> = replacing.map(<[OutPoint]>::to_vec);
        let operator_general_pubkey = self.operator_general_pubkey;
        async move {
            // Both strategies funnel through the same `build_cpfp_child` machinery — only
            // the foreign-UTXO descriptor (anchor vs. payout) differs.
            let parent_fee = strategy.parent_fee();
            let foreign = match strategy {
                CpfpStrategy::AnchorBearing {
                    anchor_vout,
                    anchor_internal_key,
                    ..
                } => AnchorInfo::KeyPath {
                    vout: anchor_vout,
                    internal_key: anchor_internal_key,
                },
                CpfpStrategy::ParentTxCombined {
                    payout_outpoint, ..
                } => AnchorInfo::KeyPath {
                    vout: payout_outpoint.vout,
                    internal_key: operator_general_pubkey,
                },
                CpfpStrategy::MultiAnchorBearing {
                    anchor_vout,
                    leaf_script,
                    control_block,
                    ..
                } => AnchorInfo::ScriptPath {
                    vout: anchor_vout,
                    leaf_script,
                    control_block,
                },
            };
            let mut wallet = wallet_arc.write().await;
            let funded = wallet
                .build_cpfp_child(
                    &parent_owned,
                    parent_fee,
                    foreign,
                    target_pkg_fee_rate,
                    replacing_owned.as_deref(),
                )
                .await
                .map_err(|e| format!("{e}"))?;
            let spent = funded.spent();
            Ok(WalletFundedPsbt {
                psbt: funded.psbt,
                spent,
            })
        }
    }
}

/// [`CpfpFeeSource`] backed by `bitcoind`'s `estimatesmartfee`.
///
/// Floors the result at 1 sat/vB. `estimatesmartfee` reports no rate at all when it has too
/// little data to work with (a fresh regtest, an early signet), and can report below min-relay
/// on a quiet network — either way the bump loop must not target a rate that would leave the
/// package unrelayable.
#[derive(Debug)]
pub struct BitcoindCpfpFeeSource {
    client: Arc<BitcoinClient>,
    conf_target: u16,
}

impl BitcoindCpfpFeeSource {
    /// Constructs a fee source that polls `client.estimate_smart_fee(conf_target)` each call.
    pub const fn new(client: Arc<BitcoinClient>, conf_target: u16) -> Self {
        Self {
            client,
            conf_target,
        }
    }
}

impl CpfpFeeSource for BitcoindCpfpFeeSource {
    fn estimate(&self) -> impl std::future::Future<Output = Result<FeeRate, String>> + Send {
        let client = self.client.clone();
        let conf_target = self.conf_target;
        async move {
            let smart_fee = client
                .estimate_smart_fee(conf_target)
                .await
                .map_err(|e| format!("estimate_smart_fee: {e:?}"))?;
            // `estimatesmartfee` reports no `fee_rate` when it has insufficient data (fresh
            // regtest, early signet); floor at 1 sat/vB in that case and whenever the node
            // reports something below it, so the bump loop never targets a rate that would
            // leave the package below min-relay.
            let floor = FeeRate::from_sat_per_vb(1).expect("1 sat/vB is always a valid FeeRate");
            Ok(smart_fee.fee_rate.unwrap_or(floor).max(floor))
        }
    }
}

/// [`CpfpMempool`] backed by the typed
/// [`btc_tracker::submitpackage::submit_package`] wrapper over [`BitcoinClient`].
#[derive(Debug)]
pub struct BitcoindCpfpMempool {
    client: Arc<BitcoinClient>,
}

impl BitcoindCpfpMempool {
    /// Constructs a submitter forwarding to the given Bitcoin Core client.
    pub const fn new(client: Arc<BitcoinClient>) -> Self {
        Self { client }
    }
}

impl CpfpMempool for BitcoindCpfpMempool {
    fn submit_package(
        &self,
        txs: &[Transaction],
    ) -> impl std::future::Future<Output = Result<SubmitPackageSummary, SubmitPackageError>> + Send
    {
        let client = self.client.clone();
        let txs = txs.to_vec();
        async move { submitpackage::submit_package(client.as_ref(), &txs).await }
    }

    fn anchor_spend_state(
        &self,
        anchor: OutPoint,
    ) -> impl std::future::Future<Output = Result<AnchorSpendState, String>> + Send {
        let client = self.client.clone();
        async move {
            // `gettxspendingprevout` reports the transaction that spends an outpoint, whether
            // that transaction sits in the mempool or in a block. Core 24.0 added it, and the
            // bridge already needs Core 24.0 for `submitpackage`. The typed surface of the
            // client does not cover it, so call it raw.
            let query =
                serde_json::json!([{ "txid": anchor.txid.to_string(), "vout": anchor.vout }]);
            let spends: Vec<PrevoutSpend> = client
                .call_raw("gettxspendingprevout", &[query])
                .await
                .map_err(|e| format!("gettxspendingprevout: {e:?}"))?;

            let Some(spending_txid) = spends.into_iter().find_map(|s| s.spending_txid) else {
                return Ok(AnchorSpendState::Unspent);
            };

            // A spender exists. When the mempool holds it, its ancestor totals give the package
            // rate that this operator competes against.
            //
            // When the mempool does not hold it, the spender is confirmed and no child can
            // improve the parent. A transient RPC failure reads the same way here. The cost of
            // that confusion is one skipped bump, and the next trigger retries.
            let entry: Result<MempoolEntry, _> = client
                .call_raw("getmempoolentry", &[serde_json::json!(spending_txid)])
                .await;
            let Ok(entry) = entry else {
                return Ok(AnchorSpendState::Confirmed);
            };

            let ancestor_fee = Amount::from_btc(entry.fees.ancestor)
                .map_err(|e| format!("ancestor fee is not a valid amount: {e}"))?;
            let rate = ancestor_fee
                .checked_div(entry.ancestor_size.max(1))
                .map(|per_vb| FeeRate::from_sat_per_vb_unchecked(per_vb.to_sat()))
                .ok_or_else(|| "ancestor fee rate overflowed".to_string())?;
            Ok(AnchorSpendState::SpentInMempool(rate))
        }
    }
}

/// One entry of a `gettxspendingprevout` response.
#[derive(Debug, serde::Deserialize)]
struct PrevoutSpend {
    /// Absent when nothing spends the outpoint.
    #[serde(rename = "spendingtxid")]
    spending_txid: Option<String>,
}

/// The subset of `getmempoolentry` that the bump loop reads.
#[derive(Debug, serde::Deserialize)]
struct MempoolEntry {
    fees: MempoolEntryFees,
    #[serde(rename = "ancestorsize")]
    ancestor_size: u64,
}

/// Fee totals of a mempool entry, denominated in BTC as bitcoind reports them.
#[derive(Debug, serde::Deserialize)]
struct MempoolEntryFees {
    /// Total fee of this transaction and its unconfirmed ancestors.
    ancestor: f64,
}

/// Looks for a keyed-Taproot anchor on `parent.output` keyed to `anchor_pubkey`, and if
/// found returns the corresponding [`CpfpStrategy::AnchorBearing`].
///
/// `anchor_pubkey` must be the **musig2-signer** pubkey (the "btc key" from the operator
/// table) — every bridge-graph tx (claim, stake, unstaking_intent, counterproof, ack)
/// constructs its `KeyedAnchor` (from `strata_bridge_tx_graph::prelude`) with that
/// key as the internal Taproot key. The dust value comes from [`fee::anchor_dust_value`] so
/// the helper tracks any future change to the bridge's anchor sizing.
///
/// `parent_fee` must be provided by the caller; an accurate value is critical to the CPFP
/// math (the child's vbytes-to-cover-the-package depends on what the parent already pays).
pub fn infer_anchor_strategy(
    parent: &Transaction,
    anchor_pubkey: XOnlyPublicKey,
    network: Network,
    parent_fee: Amount,
) -> Option<CpfpStrategy> {
    let anchor_value = fee::anchor_dust_value();
    let expected_script = Address::p2tr(SECP256K1, anchor_pubkey, None, network).script_pubkey();
    let matches: Vec<u32> = parent
        .output
        .iter()
        .enumerate()
        .filter_map(|(vout, txout)| {
            (txout.value == anchor_value && txout.script_pubkey == expected_script)
                .then(|| u32::try_from(vout).ok())
                .flatten()
        })
        .collect();
    // Bridge txs are constructed with at most one operator-keyed anchor output. If a future
    // refactor accidentally produces a tx with two outputs that both match (same script + same
    // dust value), `find_map`-style "first match" would silently pick the wrong one — make
    // the assumption explicit.
    debug_assert!(
        matches.len() <= 1,
        "parent tx has {} outputs matching the operator-keyed anchor pattern; expected ≤ 1",
        matches.len()
    );
    matches
        .first()
        .map(|&anchor_vout| CpfpStrategy::AnchorBearing {
            anchor_vout,
            anchor_internal_key: anchor_pubkey,
            parent_fee,
        })
}

/// Builds the script-path anchor signer used for `MultiAnchor` CPFP children.
///
/// Identical key to [`build_anchor_input_signer`] — the operator's musig2 signer, which doubles
/// as its watchtower key — but signs **untweaked**. A script-path spend satisfies the leaf
/// directly, so the signature must be over the raw key rather than the BIP-341 tap-tweaked
/// output key. This is the same mode `publish_contest` already uses when signing the contest
/// transaction's own input.
pub fn build_multi_anchor_signer(s2_client: SecretServiceClient) -> InputSigner {
    let s2 = Arc::new(s2_client);
    let signer: InputSigner = Arc::new(move |msg: Message| {
        let s2 = s2.clone();
        let fut: InputSignFut = Box::pin(async move {
            let digest: &[u8; 32] = msg.as_ref();
            let sig = s2
                .musig2_signer()
                .sign_no_tweak(digest)
                .await
                .map_err(|e| {
                    warn!(?e, "secret-service multi-anchor (script-path) sign failed");
                    format!("{e:?}")
                })?;
            Ok::<Signature, String>(sig)
        });
        fut
    });
    signer
}

/// Constructs the [`InputSigner`] closure that signs the **anchor input** of a CPFP child.
///
/// Wraps `s2.musig2_signer().sign(digest, None)` — the bridge constructs every keyed anchor
/// with the operator's musig2-signer pubkey as the internal Taproot key (see
/// [`bridge-sm::graph::context`](strata_bridge_sm) `generate_key_data`, which feeds
/// `OperatorTable::idx_to_btc_key` into `KeyData::operator_pubkey`). The `None` tweak
/// applies the BIP-341 tap-tweak with an empty merkle root, matching how the anchor was
/// constructed (keyed-Taproot, no script tree).
pub fn build_anchor_input_signer(s2_client: SecretServiceClient) -> InputSigner {
    let s2 = Arc::new(s2_client);
    let signer: InputSigner = Arc::new(move |msg: Message| {
        let s2 = s2.clone();
        let fut: InputSignFut = Box::pin(async move {
            let digest: &[u8; 32] = msg.as_ref();
            let sig = s2.musig2_signer().sign(digest, None).await.map_err(|e| {
                warn!(?e, "secret-service anchor sign failed");
                format!("{e:?}")
            })?;
            Ok::<Signature, String>(sig)
        });
        fut
    });
    signer
}

/// Constructs the [`InputSigner`] closure that signs the **wallet funding inputs** of a CPFP
/// child.
///
/// Wraps `s2.general_wallet_signer().sign(digest, None)` — the operator-wallet's
/// `tr(general_pubkey)` descriptor keys its UTXOs to the general-wallet signer's pubkey, so
/// every funding input the child consumes is signed by that signer. As with the anchor
/// signer, `None` applies the BIP-341 tap-tweak with an empty merkle root.
pub fn build_wallet_input_signer(s2_client: SecretServiceClient) -> InputSigner {
    let s2 = Arc::new(s2_client);
    let signer: InputSigner = Arc::new(move |msg: Message| {
        let s2 = s2.clone();
        let fut: InputSignFut = Box::pin(async move {
            let digest: &[u8; 32] = msg.as_ref();
            let sig = s2
                .general_wallet_signer()
                .sign(digest, None)
                .await
                .map_err(|e| {
                    warn!(?e, "secret-service wallet-input sign failed");
                    format!("{e:?}")
                })?;
            Ok::<Signature, String>(sig)
        });
        fut
    });
    signer
}

/// Derives the script-path spend material for one leaf of a [`MultiAnchor`] CPFP output.
///
/// `leaf_index` is the *dense per-graph watchtower slot* — the same value the state machine
/// computes with `watchtower_slot_for_operator` and ships in the publishing duty. It is not a
/// global operator index.
///
/// Mirrors what [`Connector::finalize_input`] does when satisfying a script-path spend, but
/// hands the pieces back rather than writing them into a PSBT, because the CPFP child is built
/// and signed a step at a time by the bump loop.
///
/// Returns `None` when `leaf_index` is out of range for this anchor, which would mean the caller
/// believes it is a watchtower of a graph whose anchor says otherwise.
pub fn multi_anchor_spend_material(
    anchor: &MultiAnchor,
    leaf_index: usize,
) -> Option<(ScriptBuf, ControlBlock)> {
    let leaf_script = anchor.leaf_scripts().into_iter().nth(leaf_index)?;
    let control_block = anchor
        .spend_info()
        .control_block(&(leaf_script.clone(), LeafVersion::TapScript))?;
    Some((leaf_script, control_block))
}
