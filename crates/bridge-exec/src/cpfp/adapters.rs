//! The concrete wallet, mempool, and signers behind the [`ladder`](super::ladder).

use std::{fmt, future::Future, num::NonZeroU64, sync::Arc};

use async_trait::async_trait;
use bitcoin::{
    Amount, FeeRate, ScriptBuf, Transaction, TxOut, Txid, Witness,
    secp256k1::{Message, schnorr::Signature},
    taproot::{ControlBlock, LeafVersion},
};
use bitcoind_async_client::{Client as BitcoinClient, error::ClientError, traits::Reader};
use btc_tracker::cpfp::CpfpStrategy;
use operator_wallet::{
    Error as WalletError, FundingInput, Lease, OperatorWallet, ReplacedChild, WalletStore,
};
use secret_service_client::SecretServiceClient;
use secret_service_proto::v2::traits::{SchnorrSigner, SecretService};
use strata_bridge_connectors::{Connector, prelude::MultiAnchor};
use tokio::sync::RwLock;

use super::{
    errors::{CpfpWalletError, MempoolError, SignerError},
    interfaces::{
        CpfpMempool, CpfpWallet, FundingLease, InputSignFut, InputSigner, MempoolChild,
        ParentProbe, WalletFundedPsbt,
    },
    submitpackage::{self, SubmitPackageError, SubmitPackageSummary},
};
use crate::{chain::fetch_prevouts, fees::SAT_PER_KWU_PER_SAT_PER_VB};

/// Wraps the bridge's shared wallet handle and implements [`CpfpWallet`] over it.
///
/// Every [`ChildSpend`](strata_bridge_primitives::cpfp::ChildSpend) funnels through
/// [`OperatorWallet::build_cpfp_child`], which reads the spent output from the parent itself: the
/// parent can be unbroadcast at the time the child is built (`[parent, child]` goes out as a v3
/// 1P1C package), so the wallet does not know it.
#[derive(Debug)]
pub struct OperatorWalletCpfpAdapter<P: WalletStore + std::fmt::Debug + 'static> {
    wallet: Arc<RwLock<OperatorWallet<P>>>,
}

impl<P: WalletStore + std::fmt::Debug + 'static> OperatorWalletCpfpAdapter<P> {
    /// Constructs a new adapter wrapping the shared wallet handle.
    pub const fn new(wallet: Arc<RwLock<OperatorWallet<P>>>) -> Self {
        Self { wallet }
    }
}

/// The wallet's lease on the inputs of one child, and the outputs that those inputs spend.
///
/// A rebuild spends these inputs again. The wallet stops listing them once a sync observes the
/// child, so the outputs travel with the lease.
#[derive(Debug)]
struct ChildLease {
    /// The drop of this value returns the inputs to the wallet.
    lease: Lease,
    inputs: Vec<FundingInput>,
}

impl FundingLease for ChildLease {
    fn inputs(&self) -> &[FundingInput] {
        &self.inputs
    }

    fn lease(&self) -> &Lease {
        &self.lease
    }
}

/// Classifies a build error at the boundary. The driver reads this to stop bumping a parent that
/// cannot carry a child at all: the outputs of a signed parent and the size of a spend of them do
/// not change, so these two fail the same way on every attempt.
fn classify(error: WalletError) -> CpfpWalletError {
    if let WalletError::ChildAboveCap { needed, ceiling } = error {
        return CpfpWalletError::AboveCap { needed, ceiling };
    }
    let message = error.to_string();
    match error {
        WalletError::SpendVoutOutOfRange { .. } | WalletError::ChildTooLarge { .. } => {
            CpfpWalletError::Unbumpable(message)
        }
        _ => CpfpWalletError::Transient(message),
    }
}

#[async_trait]
impl<P: WalletStore + std::fmt::Debug + 'static> CpfpWallet for OperatorWalletCpfpAdapter<P> {
    async fn build_cpfp_child(
        &self,
        parent: &Transaction,
        strategy: &CpfpStrategy,
        target_pkg_fee_rate: FeeRate,
        max_package_rate: FeeRate,
        replaced: ReplacedChild<'_>,
    ) -> Result<WalletFundedPsbt, CpfpWalletError> {
        let (funded, inputs) = self
            .wallet
            .write()
            .await
            .build_cpfp_child(
                parent,
                strategy.parent_fee,
                &strategy.spend,
                target_pkg_fee_rate,
                max_package_rate,
                replaced,
            )
            .map_err(classify)?;
        let (psbt, lease) = funded.into_parts();
        Ok(WalletFundedPsbt {
            psbt,
            lease: Arc::new(ChildLease { lease, inputs }),
        })
    }

    async fn adopt_child(
        &self,
        parent: Txid,
        inputs: Vec<FundingInput>,
    ) -> Option<Arc<dyn FundingLease>> {
        let (lease, inputs) = self.wallet.read().await.adopt_cpfp_child(parent, inputs)?;
        Some(Arc::new(ChildLease { lease, inputs }))
    }

    async fn refresh(&self) -> Result<(), CpfpWalletError> {
        // Bind the result: the guard is a temporary of this statement, so it ends here.
        let synced = self.wallet.write().await.sync().await;
        synced.map_err(|e| CpfpWalletError::Transient(e.to_string()))
    }

    async fn sign_owned_inputs(
        &self,
        tx: &Transaction,
        input_indices: &[usize],
        prevouts: &[TxOut],
    ) -> Result<Vec<Option<Witness>>, SignerError> {
        // The guard ends with this statement, so the signing wait holds no wallet lock.
        let signer = self.wallet.read().await.general_signer();
        signer
            .sign_owned_inputs(tx, input_indices, prevouts)
            .await
            .map_err(|e| SignerError(e.to_string()))
    }
}

/// [`CpfpMempool`] backed by the typed
/// [`submit_package`](submitpackage::submit_package) wrapper over [`BitcoinClient`].
#[derive(Debug)]
pub struct BitcoindCpfpMempool {
    client: Arc<BitcoinClient>,
}

impl BitcoindCpfpMempool {
    /// Constructs a mempool view over the given Bitcoin Core client.
    pub const fn new(client: Arc<BitcoinClient>) -> Self {
        Self { client }
    }
}

#[async_trait]
impl CpfpMempool for BitcoindCpfpMempool {
    async fn submit_package(
        &self,
        txs: &[Transaction],
    ) -> Result<SubmitPackageSummary, SubmitPackageError> {
        submitpackage::submit_package(self.client.as_ref(), txs).await
    }

    async fn probe(&self, parent: Txid) -> Result<ParentProbe, MempoolError> {
        // `spentby` lists the direct children of a transaction, on any of its outputs. Bump
        // parents are v3, so TRUC allows one. A confirmed parent reads as `Absent`, and the
        // driver stops the bumps for it on the same event.
        let entry = match self.mempool_entry(parent).await {
            Ok(entry) => entry,
            Err(ClientError::Server(RPC_INVALID_ADDRESS_OR_KEY, _)) => {
                return Ok(ParentProbe::Absent);
            }
            Err(e) => return Err(MempoolError(format!("getmempoolentry: {e:?}"))),
        };
        let Some(txid) = entry.spent_by.first().copied() else {
            return Ok(ParentProbe::NoChild);
        };

        // A rival can replace the child between the two calls, so the entry can be gone. The
        // first call still read the parent, and the next trigger reads the new child.
        let child = match self.mempool_entry(txid).await {
            Ok(child) => child,
            Err(ClientError::Server(RPC_INVALID_ADDRESS_OR_KEY, _)) => {
                return Ok(ParentProbe::NoChild);
            }
            Err(e) => return Err(MempoolError(format!("getmempoolentry: {e:?}"))),
        };
        let fee = Amount::from_btc(child.fees.base)
            .map_err(|e| MempoolError(format!("child fee is not a valid amount: {e}")))?;
        let pkg_fee_rate =
            ancestor_fee_rate(child.fees.ancestor, child.ancestor_size).map_err(MempoolError)?;
        Ok(ParentProbe::Child(MempoolChild {
            txid,
            fee,
            vbytes: child.vsize,
            pkg_fee_rate,
        }))
    }

    async fn child_inputs(&self, child: Txid) -> Result<Vec<FundingInput>, MempoolError> {
        let child = self
            .client
            .get_raw_transaction_verbosity_zero(&child)
            .await
            .map_err(|e| MempoolError(format!("getrawtransaction: {e:?}")))?
            .0;
        let prevouts = fetch_prevouts(&self.client, &child)
            .await
            .map_err(|e| MempoolError(format!("prevouts of a child (needs txindex): {e:?}")))?;
        Ok(child
            .input
            .iter()
            .zip(prevouts)
            .map(|(input, txout)| FundingInput {
                outpoint: input.previous_output,
                txout,
            })
            .collect())
    }

    async fn min_fee_rate(&self) -> Result<FeeRate, MempoolError> {
        let info: MempoolInfo = self
            .client
            .call_raw("getmempoolinfo", &[])
            .await
            .map_err(|e| MempoolError(format!("getmempoolinfo: {e:?}")))?;
        fee_rate_of_btc_per_kvb(info.min_fee).map_err(MempoolError)
    }
}

impl BitcoindCpfpMempool {
    /// Reads the mempool entry of `txid`. The typed surface of the client does not cover the
    /// fields of the entry that the probe reads, so this calls the RPC raw.
    async fn mempool_entry(&self, txid: Txid) -> Result<MempoolEntry, ClientError> {
        self.client
            .call_raw("getmempoolentry", &[serde_json::json!(txid)])
            .await
    }
}

/// The code of the error that `getmempoolentry` returns for a transaction outside the mempool.
const RPC_INVALID_ADDRESS_OR_KEY: i32 = -5;

/// The subset of `getmempoolentry` that the probe reads.
#[derive(Debug, serde::Deserialize)]
struct MempoolEntry {
    fees: MempoolEntryFees,
    /// Size of this transaction alone.
    vsize: NonZeroU64,
    #[serde(rename = "ancestorsize")]
    ancestor_size: NonZeroU64,
    /// Direct children of this transaction in the mempool.
    #[serde(rename = "spentby")]
    spent_by: Vec<Txid>,
}

/// Fee totals of a mempool entry, denominated in BTC as bitcoind reports them.
#[derive(Debug, serde::Deserialize)]
struct MempoolEntryFees {
    /// Fee of this transaction alone.
    base: f64,
    /// Total fee of this transaction and its unconfirmed ancestors.
    ancestor: f64,
}

/// The subset of `getmempoolinfo` that a bump reads.
#[derive(Debug, serde::Deserialize)]
struct MempoolInfo {
    /// Lowest rate that the node admits, in BTC/kvB.
    #[serde(rename = "mempoolminfee")]
    min_fee: f64,
}

/// Builds the script-path anchor signer used for `MultiAnchor` CPFP children.
///
/// Identical key to [`build_anchor_input_signer`] — the operator's musig2 signer, which doubles
/// as its watchtower key — but signs **untweaked**. A script-path spend satisfies the leaf
/// directly, so the signature must be over the raw key rather than the BIP-341 tap-tweaked
/// output key. This is the same mode `publish_contest` uses when signing the contest
/// transaction's own input.
pub fn build_multi_anchor_signer(s2_client: SecretServiceClient) -> InputSigner {
    input_signer(s2_client, "multi-anchor sign", |s2, digest| async move {
        s2.musig2_signer().sign_no_tweak(&digest).await
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
    input_signer(s2_client, "anchor sign", |s2, digest| async move {
        s2.musig2_signer().sign(&digest, None).await
    })
}

/// Constructs the [`InputSigner`] closure that signs the **wallet funding inputs** of a CPFP
/// child.
///
/// Wraps `s2.general_wallet_signer().sign(digest, None)` — the operator-wallet's
/// `tr(general_pubkey)` descriptor keys its UTXOs to the general-wallet signer's pubkey, so on
/// secret-service custody this signer signs every funding input of the child. Fireblocks custody
/// signs its own inputs, and this signer does not run. As with the anchor signer, `None` applies
/// the BIP-341 tap-tweak with an empty merkle root.
pub fn build_wallet_input_signer(s2_client: SecretServiceClient) -> InputSigner {
    input_signer(s2_client, "wallet input sign", |s2, digest| async move {
        s2.general_wallet_signer().sign(&digest, None).await
    })
}

/// Wraps one secret-service signature call as an [`InputSigner`]. `label` names the signer in an
/// error.
fn input_signer<F, Fut, E>(
    s2_client: SecretServiceClient,
    label: &'static str,
    sign: F,
) -> InputSigner
where
    F: Fn(Arc<SecretServiceClient>, [u8; 32]) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Signature, E>> + Send + 'static,
    E: fmt::Debug,
{
    let s2 = Arc::new(s2_client);
    Arc::new(move |msg: Message| {
        let signature = sign(s2.clone(), *msg.as_ref());
        let fut: InputSignFut = Box::pin(async move {
            signature
                .await
                .map_err(|e| SignerError(format!("{label}: {e:?}")))
        });
        fut
    })
}

/// Derives the script-path spend material for one leaf of a [`MultiAnchor`] CPFP output.
///
/// `leaf_index` is the position of the signing key in the list that built the anchor. For a graph
/// anchor that is the dense per-graph watchtower slot, which the state machine computes with
/// `watchtower_slot_for_operator`. It is not a global operator index.
///
/// Mirrors what [`Connector::finalize_input`] does when satisfying a script-path spend, but
/// hands the pieces back rather than writing them into a PSBT, because the CPFP child is built
/// and signed a step at a time by a bump.
///
/// Returns `None` when `leaf_index` is out of range for this anchor.
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

/// Computes the package rate from the ancestor totals `getmempoolentry` reports.
///
/// The rate keeps sat/kwu precision, the unit of `FeeRate`, so that a child at a fractional
/// target compares equal to the target. It truncates to one sat/kwu (1/250 sat/vB), the smallest
/// step `FeeRate` can express.
fn ancestor_fee_rate(ancestor_fee_btc: f64, ancestor_size: NonZeroU64) -> Result<FeeRate, String> {
    let fee_sat = Amount::from_btc(ancestor_fee_btc)
        .map_err(|e| format!("ancestor fee is not a valid amount: {e}"))?
        .to_sat();
    let sat_per_kwu = fee_sat.saturating_mul(SAT_PER_KWU_PER_SAT_PER_VB) / ancestor_size;
    Ok(FeeRate::from_sat_per_kwu(sat_per_kwu))
}

/// Converts the BTC/kvB rate that bitcoind reports, rounded up: a rate rounded down can refuse a
/// package at the boundary.
fn fee_rate_of_btc_per_kvb(rate: f64) -> Result<FeeRate, String> {
    let sat_per_kvb = Amount::from_btc(rate)
        .map_err(|e| format!("minimum fee rate is not a valid amount: {e}"))?
        .to_sat();
    Ok(FeeRate::from_sat_per_kwu(sat_per_kvb.div_ceil(4)))
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;

    use super::*;

    fn vbytes(size: u64) -> NonZeroU64 {
        NonZeroU64::new(size).expect("a test size is not zero")
    }

    /// Each wallet error maps to the driver behaviour it needs: a shape error stops the bumps,
    /// a refusal at the cap stays typed, and a shortage retries.
    #[test]
    fn a_wallet_error_maps_to_what_the_driver_needs() {
        assert!(matches!(
            classify(WalletError::SpendVoutOutOfRange {
                vout: 5,
                parent_outputs: 1,
            }),
            CpfpWalletError::Unbumpable(_)
        ));
        assert!(matches!(
            classify(WalletError::ChildTooLarge { vbytes: 1_100 }),
            CpfpWalletError::Unbumpable(_)
        ));
        assert!(matches!(
            classify(WalletError::ChildAboveCap {
                needed: Amount::from_sat(2),
                ceiling: Amount::from_sat(1),
            }),
            CpfpWalletError::AboveCap { .. }
        ));
        assert!(matches!(
            classify(WalletError::InsufficientFunds {
                available: Amount::ZERO,
                needed: Amount::from_sat(1),
            }),
            CpfpWalletError::Transient(_)
        ));
    }

    /// 1005 sat over 100 vB is 10.05 sat/vB, which is 2512 sat/kwu.
    #[test]
    fn the_ancestor_rate_keeps_fractional_sat_per_vb() {
        // 1005 sat is 0.00001005 BTC; the float round-trips to 1005 sat.
        let rate = ancestor_fee_rate(0.00001005_f64, vbytes(100)).expect("valid inputs");
        assert_eq!(rate.to_sat_per_kwu(), 2512);
    }

    /// 1 sat over 3 vB is 83.33 sat/kwu.
    #[test]
    fn the_ancestor_rate_keeps_a_tiny_fee() {
        let rate = ancestor_fee_rate(0.00000001_f64, vbytes(3)).expect("valid inputs");
        assert_eq!(rate.to_sat_per_kwu(), 83);
    }

    /// 0.00001 BTC/kvB is the default 1 sat/vB relay floor, which is 250 sat/kwu.
    #[test]
    fn the_node_minimum_converts_from_btc_per_kvb() {
        let rate = fee_rate_of_btc_per_kvb(0.00001_f64).expect("valid input");
        assert_eq!(rate, FeeRate::from_sat_per_vb_unchecked(1));
    }

    /// A rate between two sat/kwu values rounds up: 1 sat/kvB is 0.25 sat/kwu.
    #[test]
    fn the_node_minimum_rounds_up() {
        let rate = fee_rate_of_btc_per_kvb(0.00000001_f64).expect("valid input");
        assert_eq!(rate.to_sat_per_kwu(), 1);
    }

    /// A parent with a child in the mempool names it in `spentby`, and `fees.base` and `vsize`
    /// describe the child alone.
    #[test]
    fn a_mempool_entry_reads_the_fields_of_a_child() {
        let txid = Txid::from_byte_array([7; 32]);
        let entry: MempoolEntry = serde_json::from_value(serde_json::json!({
            "vsize": 202,
            "ancestorsize": 662,
            "spentby": [txid],
            "fees": { "base": 0.0001, "modified": 0.0001, "ancestor": 0.0002, "descendant": 0.0001 },
        }))
        .expect("the entry must parse");
        assert_eq!(entry.spent_by, vec![txid]);
        assert_eq!(entry.vsize.get(), 202);
        assert_eq!(entry.ancestor_size.get(), 662);
        assert_eq!(Amount::from_btc(entry.fees.base).unwrap().to_sat(), 10_000);
    }
}
