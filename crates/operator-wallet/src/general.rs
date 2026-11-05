//! The operator's general-purpose funds: the wallet that fronts payments, pays CPFP fees, and tops
//! up other internal pools.
//!
//! The custody tracks its script on the operator's own node through one
//! [`TrackedWallet`](crate::TrackedWallet), so the composer [`crate::OperatorWallet`] reads one
//! chain view whoever signs. Custody decides only the script, the size of a signed input, and who
//! signs. Leases, the reserved wallet, input selection, and transaction construction live on the
//! composer.

pub mod native;

use std::{collections::HashSet, error::Error as StdError};

use bdk_wallet::{
    bitcoin::{
        transaction::InputWeightPrediction, Amount, FeeRate, OutPoint, Psbt, ScriptBuf,
        Transaction, TxOut, Txid, Witness, XOnlyPublicKey,
    },
    chain::ChainPosition,
    descriptor,
    descriptor::ExtendedDescriptor,
    LocalOutput,
};

/// Who holds the general funds, and the store of the chain view of their script.
#[derive(Debug)]
pub enum GeneralCustody<P> {
    /// The secret-service general key. Signing happens downstream, through the secret-service
    /// client, so the wallet only plans.
    SecretService {
        /// The x-only key of the general wallet, which `tr(general_key)` scripts pay.
        general_key: XOnlyPublicKey,
        /// Store of the chain view.
        store: P,
    },
}

impl<P> GeneralCustody<P> {
    /// The descriptor the view tracks, the signer of its inputs, and the store.
    pub(crate) fn into_parts(self) -> (ExtendedDescriptor, GeneralSigner, P) {
        match self {
            Self::SecretService { general_key, store } => {
                let (descriptor, ..) = descriptor!(tr(general_key)).expect("valid tr() descriptor");
                (descriptor, GeneralSigner::SecretService, store)
            }
        }
    }
}

/// A signing failure of the custody. A later attempt signs afresh, so a caller treats every error
/// as transient.
pub type GeneralSignError = Box<dyn std::error::Error + Send + Sync>;

/// Who signs the general-wallet inputs of a transaction.
#[derive(Debug, Clone)]
pub enum GeneralSigner {
    /// Secret-service: the caller signs through its client after the wallet plans.
    SecretService,
}

impl GeneralSigner {
    /// Size of one signed input of this custody, which the planner prices.
    pub const fn input_prediction(&self) -> InputWeightPrediction {
        match self {
            Self::SecretService => InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
        }
    }

    /// Signs the inputs at `input_indices` of `tx` that this custody holds the key for. A `None`
    /// witness is an input that the caller signs downstream, which is every input of the
    /// secret-service custody.
    pub async fn sign_owned_inputs(
        &self,
        _tx: &Transaction,
        input_indices: &[usize],
        _prevouts: &[TxOut],
    ) -> Result<Vec<Option<Witness>>, GeneralSignError> {
        match self {
            Self::SecretService => Ok(vec![None; input_indices.len()]),
        }
    }
}

/// A backend that manages the operator's general-purpose Bitcoin funds.
///
/// The trait is intentionally narrow: it covers UTXO discovery + signing + transaction
/// construction for the general wallet only. Lease bookkeeping, the reserved wallet, and
/// anchor handling live on the composer.
///
/// # Signing contract
///
/// A backend signs the inputs it has key material for. Inputs it leaves unsigned must
/// carry `witness_utxo` (and `tap_internal_key` for Taproot key-path) so the caller can
/// sign them downstream by whatever means it sees fit.
pub trait GeneralWallet: Send + Sync {
    /// Backend-specific error type.
    type Error: StdError + Send + Sync + 'static;

    /// Refreshes internal state from the underlying source. Idempotent.
    ///
    /// Takes `&mut self` because the typical native impl needs to mutate its BDK wallet
    /// state. Callers serialize via an outer lock; the trait doesn't impose interior
    /// mutability.
    fn sync(&mut self) -> impl std::future::Future<Output = Result<(), Self::Error>> + Send;

    /// Returns the receive script for this wallet. Stable across calls for native backends;
    /// may rotate for backends that mint fresh deposit addresses per call.
    fn script_pubkey(&self) -> ScriptBuf;

    /// Returns every UTXO this wallet currently controls (confirmed and unconfirmed). The
    /// caller is responsible for filtering anchors, leases, and other domain-specific
    /// exclusions before requesting funding.
    fn list_utxos(&self) -> Vec<UtxoInfo>;

    /// Every outpoint the wallet still holds unspent, including any [`Self::list_utxos`] leaves
    /// out.
    ///
    /// Lease bookkeeping asks this rather than [`Self::list_utxos`]: a lease must only be released
    /// once the outpoint has actually been spent, not because the wallet has stopped trusting it
    /// for spending. Releasing early would let two callers lease the same outpoint.
    fn unspent_outpoints(&self) -> Vec<OutPoint>;

    /// Builds a v3 TRUC funding transaction and signs the inputs it has key material for.
    ///
    /// * `outputs` — recipient outputs to fund. Change (if any) is appended.
    /// * `explicit_inputs` — when `Some`, only these outpoints are used as inputs. When `None`, the
    ///   backend selects inputs from its spendable UTXO set, skipping `exclude`.
    /// * `fee_rate` — target sat-per-vbyte for the transaction itself.
    /// * `exclude` — outpoints the backend must not select (anchors, currently-leased outpoints,
    ///   etc.). Ignored when `explicit_inputs` is `Some`.
    ///
    /// Inputs the backend can sign are returned with their witnesses populated; the rest
    /// carry `witness_utxo` and `tap_internal_key` (for Taproot) so the caller can sign
    /// downstream.
    fn fund_v3_transaction(
        &mut self,
        outputs: Vec<TxOut>,
        explicit_inputs: Option<&[OutPoint]>,
        fee_rate: FeeRate,
        exclude: &[OutPoint],
    ) -> impl std::future::Future<Output = Result<FundedPsbt, Self::Error>> + Send;

    /// Builds a v3 TRUC CPFP child for `parent`, spending the keyed-Taproot anchor at
    /// `parent.output[anchor_vout]` plus one fee-paying input drawn from this wallet.
    ///
    /// * `target_pkg_fee_rate` — sat-per-vbyte target for the (parent, child) package as a whole.
    /// * `exclude` — fee-paying-input selection skips these outpoints. Used to avoid re-selecting
    ///   the funding input of a prior child being replaced via RBF.
    ///
    /// Per the trait-level signing contract, the anchor input is left unsigned with
    /// `witness_utxo` and `tap_internal_key` populated; the fee-paying input is signed iff
    /// the backend holds its key material.
    fn build_cpfp_child(
        &mut self,
        parent: &Transaction,
        anchor_vout: u32,
        target_pkg_fee_rate: FeeRate,
        exclude: &[OutPoint],
    ) -> impl std::future::Future<Output = Result<FundedPsbt, Self::Error>> + Send;
}

/// A funded PSBT returned by [`GeneralWallet`] funding operations.
#[derive(Debug, Clone)]
pub struct FundedPsbt {
    /// The funded PSBT. See the [`GeneralWallet`] signing contract for which inputs are
    /// signed vs. left for downstream signing.
    pub psbt: Psbt,
}

impl FundedPsbt {
    /// Returns the outpoints consumed as inputs to this PSBT, derived from
    /// `psbt.unsigned_tx`. Use this to lease the spent UTXOs against re-selection by
    /// concurrent callers.
    pub fn spent(&self) -> Vec<OutPoint> {
        self.psbt
            .unsigned_tx
            .input
            .iter()
            .map(|txin| txin.previous_output)
            .collect()
    }
}

/// A snapshot of a single UTXO controlled by a [`GeneralWallet`] (or, by convention, the
/// reserved wallet that the [`crate::OperatorWallet`] composer manages internally).
#[derive(Debug, Clone)]
pub struct UtxoInfo {
    /// Outpoint identifying this UTXO.
    pub outpoint: OutPoint,
    /// Output amount.
    pub amount: Amount,
    /// Confirmations as of the most recent sync. `0` if the UTXO is in the mempool only
    /// (not yet on chain).
    pub confirmations: u32,
    /// Output script.
    pub script_pubkey: ScriptBuf,
}

impl From<UtxoInfo> for TxOut {
    fn from(u: UtxoInfo) -> Self {
        Self {
            value: u.amount,
            script_pubkey: u.script_pubkey,
        }
    }
}

impl From<&UtxoInfo> for TxOut {
    fn from(u: &UtxoInfo) -> Self {
        Self {
            value: u.amount,
            script_pubkey: u.script_pubkey.clone(),
        }
    }
}

/// Whether an output is spendable, given the mempool as of the last sync.
///
/// This BDK version cannot evict a transaction, so one reorged out of the chain and not
/// re-broadcast stays canonical and its outputs keep looking spendable; an unconfirmed output
/// therefore counts only while its transaction is in the mempool. An output *consumed* by such a
/// transaction stays hidden until a restart, matching BDK's own coin selection; nothing about the
/// transaction survives a load (see [`prune_stale_anchors`](crate::persist::prune_stale_anchors)).
pub(crate) fn is_spendable(output: &LocalOutput, mempool: &HashSet<Txid>) -> bool {
    match output.chain_position {
        ChainPosition::Confirmed { .. } => true,
        ChainPosition::Unconfirmed { .. } => mempool.contains(&output.outpoint.txid),
    }
}

/// Converts a BDK [`bdk_wallet::LocalOutput`] into a backend-neutral [`UtxoInfo`], computing
/// confirmations against `tip_height`. Shared between the native general-wallet backend and
/// the composer's reserved-wallet lookup since both are BDK-backed.
pub(crate) fn local_output_to_utxo_info(lo: &bdk_wallet::LocalOutput, tip_height: u32) -> UtxoInfo {
    let confirmations = match &lo.chain_position {
        ChainPosition::Confirmed { anchor, .. } => tip_height
            .saturating_sub(anchor.block_id.height)
            .saturating_add(1),
        ChainPosition::Unconfirmed { .. } => 0,
    };
    UtxoInfo {
        outpoint: lo.outpoint,
        amount: lo.txout.value,
        confirmations,
        script_pubkey: lo.txout.script_pubkey.clone(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bdk_wallet::{
        bitcoin::{
            absolute::LockTime,
            hashes::Hash,
            secp256k1::{Keypair, Secp256k1, SecretKey},
            transaction::Version,
            Amount, BlockHash, Network, Sequence, TxIn, Witness,
        },
        chain::{BlockId, CheckPoint, ConfirmationBlockTime, TxUpdate},
        descriptor, KeychainKind, Update, Wallet,
    };

    use super::*;

    fn block(height: u32, tag: u8) -> BlockId {
        BlockId {
            height,
            hash: BlockHash::from_byte_array([tag; 32]),
        }
    }

    /// A descriptor-only wallet and the script it owns.
    fn wallet(seed: u8) -> (Wallet, ScriptBuf) {
        let secret = SecretKey::from_slice(&[seed; 32]).expect("valid scalar");
        let key = Keypair::from_secret_key(&Secp256k1::new(), &secret)
            .x_only_public_key()
            .0;
        let (desc, ..) = descriptor!(tr(key)).expect("valid descriptor");
        let wallet = Wallet::create_single(desc)
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .expect("wallet");
        let script = wallet
            .peek_address(KeychainKind::External, 0)
            .address
            .script_pubkey();
        (wallet, script)
    }

    /// An arbitrary outpoint to spend. Never null: BDK treats a null input as a coinbase, which
    /// it refuses to see unconfirmed.
    fn source(tag: u8) -> OutPoint {
        OutPoint {
            txid: Txid::from_byte_array([tag; 32]),
            vout: 0,
        }
    }

    /// A transaction spending `source` and paying `sats` to `script`.
    fn pay(source: OutPoint, script: &ScriptBuf, sats: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: source,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(sats),
                script_pubkey: script.clone(),
            }],
        }
    }

    /// Sets the wallet's chain to `blocks` and applies each transaction, anchored at the given
    /// block or, with `None`, seen in the mempool.
    fn apply(wallet: &mut Wallet, blocks: &[BlockId], txs: &[(&Transaction, Option<BlockId>)]) {
        let mut update = TxUpdate::default();
        for (tx, at) in txs {
            update.txs.push(Arc::new((*tx).clone()));
            match at {
                Some(block) => {
                    let anchor = ConfirmationBlockTime {
                        block_id: *block,
                        confirmation_time: u64::from(block.height) * 600,
                    };
                    update.anchors.insert((anchor, tx.compute_txid()));
                }
                None => {
                    update.seen_ats.insert(tx.compute_txid(), 1_000);
                }
            }
        }
        wallet
            .apply_update(Update {
                chain: Some(CheckPoint::from_block_ids(blocks.iter().copied()).expect("ascending")),
                tx_update: update,
                ..Update::default()
            })
            .expect("apply update");
    }

    fn spendable(wallet: &Wallet, mempool: &HashSet<Txid>) -> Vec<LocalOutput> {
        wallet
            .list_unspent()
            .filter(|output| is_spendable(output, mempool))
            .collect()
    }

    /// A payment seen in the mempool, confirmed, then reorged out and gone from the mempool. BDK
    /// keeps its stale mempool sighting, so only the current mempool tells it from a live payment.
    #[test]
    fn a_payment_reorged_out_of_the_chain_is_not_spendable() {
        let (mut wallet, script) = wallet(9);
        let genesis = wallet.latest_checkpoint().block_id();
        let payment = pay(source(1), &script, 100_000);
        let seen = HashSet::from([payment.compute_txid()]);
        let h1 = block(1, 1);

        apply(&mut wallet, &[genesis], &[(&payment, None)]);
        assert_eq!(spendable(&wallet, &seen).len(), 1, "in the mempool");

        apply(&mut wallet, &[genesis, h1], &[(&payment, Some(h1))]);
        assert_eq!(spendable(&wallet, &HashSet::new()).len(), 1, "confirmed");

        apply(&mut wallet, &[genesis, block(1, 11)], &[]);
        assert!(
            matches!(
                wallet.transactions().next().expect("one tx").chain_position,
                ChainPosition::Unconfirmed { last_seen: Some(_) }
            ),
            "BDK reports a stale sighting, not an absence"
        );
        assert!(
            spendable(&wallet, &HashSet::new()).is_empty(),
            "gone from the mempool, so not spendable"
        );
        assert_eq!(
            spendable(&wallet, &seen).len(),
            1,
            "re-broadcast, so spendable"
        );
    }
}
