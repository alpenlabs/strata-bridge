//! Bridge-side implementations of the [`btc_tracker::cpfp`] traits.
//!
//! `btc-tracker` defines [`CpfpWallet`], [`CpfpFeeSource`], and [`CpfpPackageSubmitter`] as
//! abstract interfaces so the crate stays at the bottom of the dependency graph. The concrete
//! adapters that wire those traits to the bridge's actual wallet, fee source, and Bitcoin Core
//! client live here.

use std::sync::Arc;

use bitcoin::{
    Address, Amount, FeeRate, Network, OutPoint, Transaction, XOnlyPublicKey,
    secp256k1::{Message, SECP256K1, schnorr::Signature},
};
use bitcoind_async_client::{Client as BitcoinClient, traits::Reader};
use btc_tracker::{
    cpfp::{
        CpfpFeeSource, CpfpPackageSubmitter, CpfpStrategy, CpfpWallet, InputSignFut, InputSigner,
        WalletFundedPsbt,
    },
    submitpackage::{self, SubmitPackageError, SubmitPackageSummary},
};
use operator_wallet::{AnchorInfo, GeneralWallet, OperatorWallet};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
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
            let foreign = match strategy {
                CpfpStrategy::AnchorBearing {
                    anchor_vout,
                    anchor_internal_key,
                    ..
                } => AnchorInfo {
                    vout: anchor_vout,
                    internal_key: anchor_internal_key,
                },
                CpfpStrategy::ParentTxCombined {
                    payout_outpoint, ..
                } => AnchorInfo {
                    vout: payout_outpoint.vout,
                    internal_key: operator_general_pubkey,
                },
            };
            let parent_fee = strategy.parent_fee();
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
/// Clamps the returned rate to ≥ 1 sat/vB; `bitcoind-async-client` represents fee rates as
/// `u64` sat/vB and truncates sub-1 rates to 0, which would otherwise lose the fee entirely
/// on networks where the upstream source can report below 1 sat/vB.
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
            let raw = client
                .estimate_smart_fee(conf_target)
                .await
                .map_err(|e| format!("estimate_smart_fee: {e:?}"))?;
            FeeRate::from_sat_per_vb(raw.max(1))
                .ok_or_else(|| format!("clamped rate {} sat/vB overflows FeeRate", raw.max(1)))
        }
    }
}

/// [`CpfpPackageSubmitter`] backed by the typed
/// [`btc_tracker::submitpackage::submit_package`] wrapper over [`BitcoinClient`].
#[derive(Debug)]
pub struct BitcoindCpfpPackageSubmitter {
    client: Arc<BitcoinClient>,
}

impl BitcoindCpfpPackageSubmitter {
    /// Constructs a submitter forwarding to the given Bitcoin Core client.
    pub const fn new(client: Arc<BitcoinClient>) -> Self {
        Self { client }
    }
}

impl CpfpPackageSubmitter for BitcoindCpfpPackageSubmitter {
    fn submit_package(
        &self,
        txs: &[Transaction],
    ) -> impl std::future::Future<Output = Result<SubmitPackageSummary, SubmitPackageError>> + Send
    {
        let client = self.client.clone();
        let txs = txs.to_vec();
        async move { submitpackage::submit_package(client.as_ref(), &txs).await }
    }
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
