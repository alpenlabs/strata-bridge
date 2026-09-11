//! Native BDK-backed implementation of [`GeneralWallet`].
//!
//! The native wallet holds the operator's general-funds descriptor (`tr(general_pubkey)`) but
//! never holds private keys. Per the [`GeneralWallet`] signing contract, every PSBT this impl
//! returns carries `witness_utxo` and `tap_internal_key` on its inputs but no signatures —
//! the caller signs downstream.
//!
//! Chain state lives in a BDK [`PersistedWallet`] backed by a caller-supplied [`WalletStore`], so
//! a restart resumes from the last persisted checkpoint instead of rescanning from genesis.

use std::{
    collections::{BTreeSet, HashSet},
    num::NonZeroU32,
};

use bdk_wallet::{
    bitcoin::{FeeRate, OutPoint, Psbt, ScriptBuf, Transaction, TxOut, Txid, XOnlyPublicKey},
    chain::BlockId,
    descriptor,
    error::CreateTxError,
    KeychainKind, TxOrdering, Wallet,
};
use thiserror::Error;
use tracing::info;

use crate::{
    config::OperatorWalletConfig,
    general::{is_spendable, local_output_to_utxo_info, FundedPsbt, GeneralWallet, UtxoInfo},
    persist::{ensure_backend_not_behind, load_or_create, InitError, PersistedWallet, WalletStore},
    sync::{Backend, SyncError},
};

/// Native BDK-backed general wallet.
#[derive(Debug)]
pub struct NativeGeneralWallet<P> {
    /// Cached at construction; the BDK descriptor doesn't change at runtime.
    script_pubkey: ScriptBuf,
    wallet: PersistedWallet<P>,
    store: P,
    sync_backend: Backend,
    persist_every_blocks: NonZeroU32,
    mempool: HashSet<Txid>,
}

impl<P: WalletStore> NativeGeneralWallet<P> {
    /// Loads the general wallet for `general_pubkey` from `store`, or creates it when the store is
    /// empty. Network and persistence cadence come from `config`, shared with the reserved wallet.
    /// See [`load_or_create`] for the identity checks and the role of `bootstrap_checkpoint`.
    pub async fn load_or_create(
        general_pubkey: XOnlyPublicKey,
        config: &OperatorWalletConfig,
        sync_backend: Backend,
        mut store: P,
        bootstrap_checkpoint: Option<BlockId>,
    ) -> Result<Self, InitError<P::Error>> {
        let (desc, ..) = descriptor!(tr(general_pubkey)).expect("valid tr() descriptor");
        let wallet = load_or_create(&mut store, desc, config.network, bootstrap_checkpoint).await?;
        ensure_backend_not_behind(&sync_backend, &wallet).await?;
        let address = wallet.peek_address(KeychainKind::External, 0).address;
        info!("general wallet address: {address}");
        Ok(Self {
            script_pubkey: address.script_pubkey(),
            wallet,
            store,
            sync_backend,
            persist_every_blocks: config.persist_every_blocks,
            mempool: HashSet::new(),
        })
    }
}

/// Error type for the native general wallet impl.
#[derive(Debug, Error)]
pub enum NativeGeneralError {
    /// BDK failed to build a transaction (insufficient funds, no UTXOs, ...).
    #[error("bdk create-tx: {0}")]
    CreateTx(#[from] CreateTxError),
    /// Chain sync (block / mempool fetch / persist) failed.
    #[error("wallet sync: {0:?}")]
    Sync(SyncError),
    /// CPFP-child building is intentionally unimplemented until STR-3439 lands.
    #[error("native build_cpfp_child not yet implemented (STR-3439)")]
    CpfpChildNotImplemented,
}

impl<P: WalletStore> GeneralWallet for NativeGeneralWallet<P> {
    type Error = NativeGeneralError;

    async fn sync(&mut self) -> Result<(), Self::Error> {
        // Cleared first so a failed sync leaves no snapshot behind, since callers may carry on
        // after one. Empty treats every unconfirmed output as unspendable.
        self.mempool.clear();
        self.mempool = self
            .sync_backend
            .sync_wallet(&mut self.wallet, &mut self.store, self.persist_every_blocks)
            .await
            .map_err(NativeGeneralError::Sync)?;
        Ok(())
    }

    fn script_pubkey(&self) -> ScriptBuf {
        self.script_pubkey.clone()
    }

    fn list_utxos(&self) -> Vec<UtxoInfo> {
        let tip = self.wallet.latest_checkpoint().height();
        self.wallet
            .list_unspent()
            .filter(|output| is_spendable(output, &self.mempool))
            .map(|lo| local_output_to_utxo_info(&lo, tip))
            .collect()
    }

    fn unspent_outpoints(&self) -> Vec<OutPoint> {
        self.wallet.list_unspent().map(|lo| lo.outpoint).collect()
    }

    async fn fund_v3_transaction(
        &mut self,
        outputs: Vec<TxOut>,
        explicit_inputs: Option<&[OutPoint]>,
        fee_rate: FeeRate,
        exclude: &[OutPoint],
    ) -> Result<FundedPsbt, Self::Error> {
        let psbt = build_v3_psbt(
            &mut self.wallet,
            &self.mempool,
            &outputs,
            explicit_inputs,
            fee_rate,
            exclude,
        )?;
        Ok(FundedPsbt { psbt })
    }

    async fn build_cpfp_child(
        &mut self,
        _parent: &Transaction,
        _anchor_vout: u32,
        _target_pkg_fee_rate: FeeRate,
        _exclude: &[OutPoint],
    ) -> Result<FundedPsbt, Self::Error> {
        // TODO: <https://alpenlabs.atlassian.net/browse/STR-3439>
        // Wire up CPFP child construction during the tx-driver / RBF work.
        Err(NativeGeneralError::CpfpChildNotImplemented)
    }
}

/// Builds a v3 (TRUC) PSBT using BDK's transaction builder, with `outputs` as recipients,
/// optional explicit input selection, the given fee rate, and `exclude` skipped during
/// auto-selection.
fn build_v3_psbt(
    wallet: &mut Wallet,
    mempool: &HashSet<Txid>,
    outputs: &[TxOut],
    explicit_inputs: Option<&[OutPoint]>,
    fee_rate: FeeRate,
    exclude: &[OutPoint],
) -> Result<Psbt, CreateTxError> {
    // BDK's own view still offers outputs `is_spendable` rejects, so the exclusion has to name
    // them rather than rely on the caller, whose `exclude` was derived from the filtered list.
    let mut exclude_set: BTreeSet<OutPoint> = exclude.iter().copied().collect();
    exclude_set.extend(
        wallet
            .list_unspent()
            .filter(|output| !is_spendable(output, mempool))
            .map(|output| output.outpoint),
    );

    let mut tx_builder = wallet.build_tx();
    tx_builder.version(3);
    tx_builder.fee_rate(fee_rate);
    tx_builder.ordering(TxOrdering::Untouched);

    match explicit_inputs {
        Some(inputs) => {
            for outpoint in inputs {
                if exclude_set.contains(outpoint) {
                    return Err(CreateTxError::UnknownUtxo);
                }
                tx_builder
                    .add_utxo(*outpoint)
                    .map_err(|_| CreateTxError::UnknownUtxo)?;
            }
            tx_builder.manually_selected_only();
        }
        None => {
            tx_builder.unspendable(exclude_set.into_iter().collect());
        }
    }

    for output in outputs {
        tx_builder.add_recipient(output.script_pubkey.clone(), output.value);
    }

    tx_builder.finish()
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
        Update,
    };

    use super::*;

    /// A wallet whose only output was paid by a transaction confirmed at height 1 and then reorged
    /// out, along with that output's outpoint and the script the wallet owns.
    fn wallet_with_a_reorged_out_payment() -> (Wallet, OutPoint, ScriptBuf, Txid) {
        let secret = SecretKey::from_slice(&[31; 32]).expect("valid scalar");
        let key = Keypair::from_secret_key(&Secp256k1::new(), &secret)
            .x_only_public_key()
            .0;
        let (desc, ..) = descriptor!(tr(key)).expect("valid descriptor");
        let mut wallet = Wallet::create_single(desc)
            .network(Network::Regtest)
            .create_wallet_no_persist()
            .expect("wallet");
        let genesis = wallet.latest_checkpoint().block_id();
        let script = wallet
            .peek_address(KeychainKind::External, 0)
            .address
            .script_pubkey();
        let payment = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                // Never null: BDK treats a null input as a coinbase, which it refuses to see
                // unconfirmed.
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([41; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000_000),
                script_pubkey: script.clone(),
            }],
        };
        let txid = payment.compute_txid();
        let block = BlockId {
            height: 1,
            hash: BlockHash::from_byte_array([1; 32]),
        };
        let chain = |blocks: [BlockId; 2]| CheckPoint::from_block_ids(blocks).expect("ascending");
        wallet
            .apply_update(Update {
                chain: Some(chain([genesis, block])),
                tx_update: TxUpdate {
                    txs: vec![Arc::new(payment)],
                    anchors: [(
                        ConfirmationBlockTime {
                            block_id: block,
                            confirmation_time: 600,
                        },
                        txid,
                    )]
                    .into_iter()
                    .collect(),
                    ..TxUpdate::default()
                },
                ..Update::default()
            })
            .expect("apply the payment");
        wallet
            .apply_update(Update {
                chain: Some(chain([
                    genesis,
                    BlockId {
                        height: 1,
                        hash: BlockHash::from_byte_array([11; 32]),
                    },
                ])),
                ..Update::default()
            })
            .expect("apply the replacement chain");
        (wallet, OutPoint { txid, vout: 0 }, script, txid)
    }

    /// BDK's coin selection still offers an output `is_spendable` rejects, so the builder has to
    /// exclude it itself rather than trust the caller's list.
    #[test]
    fn coin_selection_cannot_pick_a_reorged_out_output() {
        let (mut wallet, stale, script, txid) = wallet_with_a_reorged_out_payment();
        assert_eq!(
            wallet.list_unspent().next().map(|o| o.outpoint),
            Some(stale),
            "BDK still offers it"
        );
        let recipient = [TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: script,
        }];
        let fee_rate = FeeRate::from_sat_per_vb(2).expect("fee rate");

        let err = build_v3_psbt(
            &mut wallet,
            &HashSet::new(),
            &recipient,
            None,
            fee_rate,
            &[],
        )
        .expect_err("must not fund from a reorged-out output");
        assert!(
            matches!(err, CreateTxError::CoinSelection(_)),
            "got {err:?}"
        );

        // Explicit selection of the same outpoint is refused too.
        let err = build_v3_psbt(
            &mut wallet,
            &HashSet::new(),
            &recipient,
            Some(&[stale]),
            fee_rate,
            &[],
        )
        .expect_err("must not fund from a reorged-out output");
        assert!(matches!(err, CreateTxError::UnknownUtxo), "got {err:?}");

        // Back in the mempool, the same output funds normally.
        let mempool = HashSet::from([txid]);
        build_v3_psbt(&mut wallet, &mempool, &recipient, None, fee_rate, &[])
            .expect("a mempool payment can fund");
    }
}
