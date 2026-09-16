//! Bridge-side implementations of the [`btc_tracker::cpfp`] traits.
//!
//! `btc-tracker` defines [`CpfpWallet`], [`CpfpFeeSource`], and [`CpfpMempool`] as
//! abstract interfaces so the crate stays at the bottom of the dependency graph. The concrete
//! adapters that wire those traits to the bridge's actual wallet, fee source, and Bitcoin Core
//! client live here.

use std::sync::Arc;

use bitcoin::{
    Amount, FeeRate, OutPoint, ScriptBuf, Transaction, Txid, XOnlyPublicKey,
    secp256k1::{Message, schnorr::Signature},
    taproot::{ControlBlock, LeafVersion},
};
use bitcoind_async_client::{Client as BitcoinClient, traits::Reader};
use btc_tracker::{
    cpfp::{
        AnchorSpendState, ChildPsbt, CpfpFeeSource, CpfpMempool, CpfpStrategy, CpfpWallet,
        CpfpWalletError, FeeSourceError, FundingLease, InputSignFut, InputSigner, MempoolError,
        SignerError, WalletFundedPsbt,
    },
    submitpackage::{self, SubmitPackageError, SubmitPackageSummary},
};
use operator_wallet::{
    AnchorInfo, AnchorOwnership, AnyOperatorWallet, ErrorPermanence, Lease, ReplacedChild,
};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_connectors::{Connector, prelude::MultiAnchor};
use tokio::sync::RwLock;
use tracing::warn;

/// Wraps the bridge's `Arc<RwLock<AnyOperatorWallet>>` and implements [`CpfpWallet`] over it.
///
/// Both [`CpfpStrategy`] variants funnel through
/// [`OperatorWallet::build_cpfp_child`](operator_wallet::OperatorWallet::build_cpfp_child) with the
/// foreign-UTXO machinery — the difference between them is just which output on the parent
/// the child consumes:
/// - [`CpfpStrategy::AnchorBearing`]: a 330-sat keyed-Taproot anchor at `anchor_vout`, internal key
///   = the operator's musig2 pubkey (the "btc key" from the operator table).
/// - [`CpfpStrategy::ParentTxCombined`]: the operator's payout output at `payout_outpoint.vout`,
///   internal key = the operator's general-wallet pubkey. This holds when the payout output pays
///   the wallet's own `payout_descriptor()` (the BIP-341-tweaked general key) — guaranteed by
///   construction for the descriptor-gossip parents (cooperative payout, unstaking), but the
///   presigned-graph parents (uncontested/contested payout, counterproof nack) pay the params-file
///   covenant descriptor, which the orchestrator only WARNS about at startup when it differs from
///   the wallet. On a mismatch, signing fails downstream and the bump is skipped + retried. The
///   Fireblocks backend ignores the hint — it recognises its own vault script on the prevout and
///   signs that input itself.
///
/// Treating the payout as a foreign UTXO (rather than asking BDK to track it in the wallet's
/// UTXO set) is essential: the parent has NOT been broadcast at the time we build the child
/// (we submit `[parent, child]` as a v3 1P1C package), so BDK has no knowledge of the
/// payout outpoint. `add_foreign_utxo` accepts it with a caller-provided `witness_utxo`.
#[derive(Debug)]
pub struct OperatorWalletCpfpAdapter {
    wallet: Arc<RwLock<AnyOperatorWallet>>,
    /// Operator's general-wallet pubkey. Used as the foreign-UTXO `tap_internal_key` when
    /// CPFPing a [`CpfpStrategy::ParentTxCombined`] parent — every payout output across
    /// cooperative_payout / uncontested_payout / contested_payout / unstaking goes to the
    /// operator's payout descriptor. The descriptor is backend-dependent (the native
    /// wallet's P2TR receive script, the Fireblocks vault's P2WPKH script); the
    /// classification of a prevout as the payout is backend-agnostic.
    operator_general_pubkey: XOnlyPublicKey,
}

impl OperatorWalletCpfpAdapter {
    /// Constructs a new adapter wrapping the shared wallet handle. `operator_general_pubkey`
    /// is the operator's general-wallet x-only pubkey (typically fetched once at
    /// orchestrator startup via `s2_client.general_wallet_signer().pubkey()`).
    pub const fn new(
        wallet: Arc<RwLock<AnyOperatorWallet>>,
        operator_general_pubkey: XOnlyPublicKey,
    ) -> Self {
        Self {
            wallet,
            operator_general_pubkey,
        }
    }
}

/// Presents an [`operator_wallet::Lease`] through the [`FundingLease`] interface of
/// `btc-tracker`.
///
/// The wrapper exists because the orphan rule blocks a direct implementation: the trait
/// belongs to `btc-tracker`, the lease type belongs to `operator-wallet`, and neither is local
/// to this crate. The wrapper adds no behaviour. Dropping it drops the lease, and that is what
/// returns the outpoints to the spendable set.
#[derive(Debug)]
struct WalletFundingLease(Lease);

impl FundingLease for WalletFundingLease {
    fn outpoints(&self) -> &[OutPoint] {
        self.0.outpoints()
    }
}

impl CpfpWallet for OperatorWalletCpfpAdapter {
    fn build_cpfp_child(
        &self,
        parent: &Transaction,
        strategy: CpfpStrategy,
        target_pkg_fee_rate: FeeRate,
        replacing: Option<&dyn FundingLease>,
        prior_child_fee: Option<Amount>,
    ) -> impl std::future::Future<Output = Result<WalletFundedPsbt, CpfpWalletError>> + Send {
        // Clone what we need into the future so the returned future owns its captures.
        let wallet_arc = self.wallet.clone();
        let parent_owned = parent.clone();
        let replacing_owned: Option<Vec<OutPoint>> =
            replacing.map(|lease| lease.outpoints().to_vec());
        let operator_general_pubkey = self.operator_general_pubkey;
        // `ParentTxCombined` spends the operator's own payout output, so that output belongs
        // in the lease. Every other strategy spends an anchor keyed to a protocol key, which
        // the wallet can never select for another transaction.
        let anchor_ownership = match strategy {
            CpfpStrategy::ParentTxCombined { .. } => AnchorOwnership::Wallet,
            CpfpStrategy::AnchorBearing { .. } | CpfpStrategy::MultiAnchorBearing { .. } => {
                AnchorOwnership::Foreign
            }
        };
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
            // A shared lock: the composer serializes selection internally, so a bump does
            // not need to exclude a health probe or a descriptor read for the length of a
            // backend round trip.
            let wallet = wallet_arc.read().await;
            let funded = wallet
                .build_cpfp_child(
                    &parent_owned,
                    parent_fee,
                    foreign,
                    anchor_ownership,
                    target_pkg_fee_rate,
                    ReplacedChild {
                        inputs: replacing_owned.as_deref().unwrap_or(&[]),
                        fee: prior_child_fee,
                    },
                )
                .await
                // Classify at the boundary. The wallet knows which failures repeat for a
                // signed parent, and the driver reads that to stop bumping one that cannot
                // carry a child at all.
                .map_err(|e| {
                    let message = e.to_string();
                    if e.is_permanent() {
                        CpfpWalletError::Unbumpable(message)
                    } else {
                        CpfpWalletError::Transient(message)
                    }
                })?;
            let (psbt, lease) = funded.into_parts();
            // A contract violation is a fault of the backend build, not a property of the
            // parent, and the offending input depends on which UTXOs selection picked. The
            // next attempt selects again.
            let psbt =
                ChildPsbt::new(psbt).map_err(|e| CpfpWalletError::Transient(e.to_string()))?;
            Ok(WalletFundedPsbt {
                psbt,
                lease: Arc::new(WalletFundingLease(lease)),
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
    fn estimate(
        &self,
    ) -> impl std::future::Future<Output = Result<FeeRate, FeeSourceError>> + Send {
        let client = self.client.clone();
        let conf_target = self.conf_target;
        async move {
            let smart_fee = client
                .estimate_smart_fee(conf_target)
                .await
                .map_err(|e| FeeSourceError(format!("estimate_smart_fee: {e:?}")))?;
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
    ) -> impl std::future::Future<Output = Result<AnchorSpendState, MempoolError>> + Send {
        let client = self.client.clone();
        async move {
            // `gettxspendingprevout` reports the mempool transaction that spends an outpoint.
            // It is mempool-only: a spend that confirmed reads as `Unspent` here. Core 24.0
            // added it, and the bridge already needs Core 24.0 for `submitpackage`. The
            // typed surface of the client does not cover it, so call it raw.
            let query =
                serde_json::json!([{ "txid": anchor.txid.to_string(), "vout": anchor.vout }]);
            let spends: Vec<PrevoutSpend> = client
                .call_raw("gettxspendingprevout", &[query])
                .await
                .map_err(|e| MempoolError(format!("gettxspendingprevout: {e:?}")))?;

            let Some(spending_txid) = spends.into_iter().find_map(|s| s.spending_txid) else {
                return Ok(AnchorSpendState::Unspent);
            };
            let spending_txid: Txid = spending_txid.parse().map_err(|e| {
                MempoolError(format!("gettxspendingprevout returned a bad txid: {e}"))
            })?;

            // A spender exists. Its ancestor totals give the package rate that this operator
            // competes against.
            //
            // A failed lookup is an error, not a confirmed spend. The probe is mempool-only
            // and never reports a confirmed spend, so a spender that the first call reported
            // and the entry lookup cannot find is an RPC failure or a state divergence. The
            // ladder treats the error as "probe unavailable" and builds; the submission is
            // the authority.
            let entry: MempoolEntry = client
                .call_raw("getmempoolentry", &[serde_json::json!(spending_txid)])
                .await
                .map_err(|e| MempoolError(format!("getmempoolentry: {e:?}")))?;

            let rate = ancestor_fee_rate(entry.fees.ancestor, entry.ancestor_size)
                .map_err(MempoolError)?;
            Ok(AnchorSpendState::SpentInMempool {
                spender: spending_txid,
                pkg_fee_rate: rate,
            })
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
                    SignerError(format!("{e:?}"))
                })?;
            Ok::<Signature, SignerError>(sig)
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
                SignerError(format!("{e:?}"))
            })?;
            Ok::<Signature, SignerError>(sig)
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
                    SignerError(format!("{e:?}"))
                })?;
            Ok::<Signature, SignerError>(sig)
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

/// One vbyte is four weight units, and one kiloweight unit is 1000 weight units,
/// so one sat/vB is 250 sat per kiloweight unit.
const SAT_PER_KWU_PER_SAT_PER_VB: u64 = 250;

/// Computes the package rate from the ancestor totals `getmempoolentry` reports.
///
/// The rate is computed directly in sat/kwu — the unit `FeeRate` carries — instead of
/// dividing sat by vbytes first. Dividing first truncates the observed rate to whole
/// sat/vB, while the target is fractional sat/kwu: a child sitting at target then
/// reads as underpriced, and the rebuild floor ratchets the package to ceil(target).
/// The remaining truncation is one sat/kwu (1/250 sat/vB), the smallest step
/// `FeeRate` can express.
fn ancestor_fee_rate(ancestor_fee_btc: f64, ancestor_size: u64) -> Result<FeeRate, String> {
    let fee_sat = Amount::from_btc(ancestor_fee_btc)
        .map_err(|e| format!("ancestor fee is not a valid amount: {e}"))?
        .to_sat();
    let sat_per_kwu = fee_sat
        .checked_mul(SAT_PER_KWU_PER_SAT_PER_VB)
        .and_then(|f| f.checked_div(ancestor_size.max(1)))
        .ok_or("ancestor fee rate overflowed")?;
    Ok(FeeRate::from_sat_per_kwu(sat_per_kwu))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fractional package rate keeps its fractional part: 1005 sat over 100 vB is
    /// 10.05 sat/vB, which a sat/vB division truncates to 10 sat/vB (2500 sat/kwu) but
    /// which reads 2512 sat/kwu at the precision `FeeRate` carries (2512.5, floored).
    #[test]
    fn the_ancestor_rate_keeps_fractional_sat_per_vb() {
        // 1005 sat is 0.00001005 BTC; the float round-trips to 1005 sat.
        let rate = ancestor_fee_rate(0.00001005_f64, 100).expect("valid inputs");
        assert_eq!(rate.to_sat_per_kwu(), 2512);
    }

    /// A whole-number rate is unchanged by the precision: 2500 sat over 250 vB is 10
    /// sat/vB = 2500 sat/kwu either way.
    #[test]
    fn the_ancestor_rate_is_exact_for_whole_sat_per_vb() {
        let rate = ancestor_fee_rate(0.000025_f64, 250).expect("valid inputs");
        assert_eq!(rate.to_sat_per_kwu(), 2500);
    }

    /// A tiny fee over an odd size keeps its fraction instead of truncating to zero:
    /// 1 sat over 3 vB is 83.33... sat/kwu, not 0.
    #[test]
    fn the_ancestor_rate_does_not_truncate_a_tiny_fee_to_zero() {
        let rate = ancestor_fee_rate(0.00000001_f64, 3).expect("valid inputs");
        assert_eq!(rate.to_sat_per_kwu(), 83);
    }

    /// A sat-to-sat-kwu widening overflow is an error, not a saturating rate.
    #[test]
    fn the_ancestor_rate_rejects_an_overflow() {
        // 8e8 BTC is 8e16 sat: valid as an Amount (u64 holds ~1.8e19 sat),
        // but x250 overflows u64.
        let err = ancestor_fee_rate(8e8_f64, 1).expect_err("must overflow");
        assert_eq!(err, "ancestor fee rate overflowed");
    }
}
