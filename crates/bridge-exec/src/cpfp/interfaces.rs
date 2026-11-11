//! The wallet, mempool and signer seams of a CPFP bump.

use std::{fmt, num::NonZeroU64, sync::Arc};

use async_trait::async_trait;
use bitcoin::{
    Amount, FeeRate, Psbt, Transaction, TxOut, Txid, Witness,
    secp256k1::{Message, schnorr::Signature},
};
use btc_tracker::cpfp::CpfpStrategy;
use operator_wallet::{FundingInput, Lease, ReplacedChild};

use super::{
    errors::{CpfpWalletError, MempoolError, SignerError},
    submitpackage::{SubmitPackageError, SubmitPackageSummary},
};

/// Wallet inputs that one CPFP child holds.
///
/// The wallet frees the inputs when this value drops. The handle keeps the value for as long as
/// the child can be live, so that no other duty selects the inputs and evicts the child. A wallet
/// sync that observes the child prunes its record in the lease set, and this value still carries
/// the inputs for the next rebuild.
///
/// A trait rather than [`operator_wallet::Lease`] so that tests can observe the drop.
pub trait FundingLease: Send + Sync + fmt::Debug {
    /// The inputs that this lease holds, with the outputs they spend. The anchor input is not
    /// one of them, unless the output that the child spends belongs to the wallet.
    fn inputs(&self) -> &[FundingInput];

    /// The wallet lease behind this value. Selection for a replacement looks past it.
    fn lease(&self) -> &Lease;
}

/// A funded PSBT returned by [`CpfpWallet::build_cpfp_child`].
#[derive(Debug, Clone)]
pub struct WalletFundedPsbt {
    /// The unsigned child PSBT. Every input carries `witness_utxo`: the fee of the child and
    /// the sighash of each input read the spent outputs.
    pub psbt: Psbt,
    /// Holds the wallet inputs that the child consumes.
    pub lease: Arc<dyn FundingLease>,
}

/// What the ladder needs from the wallet: the next CPFP child, a lease on the inputs of a child
/// that the handle does not know, and a signature for each input that a wallet signer holds the
/// key for.
///
/// Building and signing are separate so that the wallet stays free while a signer waits for a
/// signature. [`perform_bump`](super::ladder::perform_bump) signs every other input itself: the
/// anchor through
/// [`CpfpContext::anchor_input_signer`](super::ladder::CpfpContext::anchor_input_signer), and a
/// wallet input the signer does not sign through
/// [`CpfpContext::wallet_input_signer`](super::ladder::CpfpContext::wallet_input_signer).
#[async_trait]
pub trait CpfpWallet: Send + Sync {
    /// Builds an unsigned CPFP child for `parent` under `strategy`, targeting
    /// `target_pkg_fee_rate` on the (parent, child) package.
    ///
    /// `max_package_rate` is a hard limit: a child past it is [`CpfpWalletError::AboveCap`].
    ///
    /// `replaced` names the live child that the new one must outbid, and the earlier children
    /// whose inputs stay available to the build. A lease over those inputs stays valid across the
    /// call: the handle drops it once a mempool accepts the new child.
    async fn build_cpfp_child(
        &self,
        parent: &Transaction,
        strategy: &CpfpStrategy,
        target_pkg_fee_rate: FeeRate,
        max_package_rate: FeeRate,
        replaced: ReplacedChild<'_>,
    ) -> Result<WalletFundedPsbt, CpfpWalletError>;

    /// Takes a lease on those of `inputs` that belong to this wallet. `None` when no input does,
    /// which means that the child belongs to another operator.
    ///
    /// `inputs` are every input of a live child of `parent`, with the outputs they spend.
    async fn adopt_child(
        &self,
        parent: Txid,
        inputs: Vec<FundingInput>,
    ) -> Option<Arc<dyn FundingLease>>;

    /// Brings the view of the wallet up to date with the node.
    ///
    /// Selection reads that view, so a bump that the view failed calls this before the next
    /// attempt: a funding failure can hide a top-up, and a rejected input is spent. The call takes
    /// the exclusive wallet guard, and no bump holds a wallet guard when it calls this.
    async fn refresh(&self) -> Result<(), CpfpWalletError>;

    /// Signs the inputs of `tx` at `input_indices` that the wallet signer holds a key for.
    /// Returns one entry per index, `None` for an input that the ladder must sign itself.
    ///
    /// `prevouts[i]` is the output spent by `tx.input[i]`.
    async fn sign_owned_inputs(
        &self,
        tx: &Transaction,
        input_indices: &[usize],
        prevouts: &[TxOut],
    ) -> Result<Vec<Option<Witness>>, SignerError>;
}

/// Boxed future returned by an [`InputSigner`]; pinned + Send so it can cross a tokio task
/// boundary.
pub type InputSignFut =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Signature, SignerError>> + Send>>;

/// Signs one Taproot input by computing a Schnorr signature over the caller-supplied sighash.
///
/// A [`CpfpContext`](super::ladder::CpfpContext) holds one signer per key and mode:
///
/// - [`CpfpContext::anchor_input_signer`](super::ladder::CpfpContext::anchor_input_signer) signs a
///   keyed anchor with the key that built it, tweaked for a key-path spend. In the bridge this is
///   the operator's musig2-signer pubkey, which also serves as its watchtower key.
/// - [`CpfpContext::wallet_input_signer`](super::ladder::CpfpContext::wallet_input_signer) signs
///   each funding input that the wallet's own signer does not sign, tweaked for a key-path spend.
///   In the bridge this is the general-wallet pubkey that secret-service holds. A Fireblocks vault
///   signs every funding input, so this signer does not run there.
pub type InputSigner = Arc<dyn Fn(Message) -> InputSignFut + Send + Sync>;

/// A mempool child of a parent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MempoolChild {
    /// Txid of the child.
    pub txid: Txid,
    /// Absolute fee of the child alone. A replacement must beat it.
    pub fee: Amount,
    /// Size of the child alone. A replacement must beat its own fee rate.
    pub vbytes: NonZeroU64,
    /// Rate that the child and its unconfirmed ancestors pay together.
    pub pkg_fee_rate: FeeRate,
}

/// What the mempool holds for a parent.
///
/// Every bump parent is a v3 transaction, so TRUC gives it one child, on any of its outputs. The
/// probe therefore reads the descendants of the parent and not the output that this operator
/// would spend. A child on another output blocks a new child in the same way as a child on the
/// same output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParentProbe {
    /// The mempool does not hold the parent. A parent that never entered, a parent that the node
    /// evicted, and a parent that confirmed all read this way.
    Absent,
    /// The mempool holds the parent, and the parent has no child.
    NoChild,
    /// The mempool holds the parent and this child of it.
    Child(MempoolChild),
}

/// The bitcoind mempool operations that a bump needs.
#[async_trait]
pub trait CpfpMempool: Send + Sync {
    /// Forwards to bitcoind's `submitpackage` RPC; returns the typed summary.
    async fn submit_package(
        &self,
        txs: &[Transaction],
    ) -> Result<SubmitPackageSummary, SubmitPackageError>;

    /// Reports what the mempool holds for `parent`.
    async fn probe(&self, parent: Txid) -> Result<ParentProbe, MempoolError>;

    /// Reads every input of the mempool transaction `child`, with the output it spends.
    async fn child_inputs(&self, child: Txid) -> Result<Vec<FundingInput>, MempoolError>;

    /// The lowest fee rate at which this node admits a package.
    async fn min_fee_rate(&self) -> Result<FeeRate, MempoolError>;
}
