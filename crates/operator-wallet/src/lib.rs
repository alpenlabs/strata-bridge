//! Operator wallet
pub mod sync;

use std::{collections::BTreeSet, time::Duration};

use algebra::predicate;
use bdk_wallet::{
    bitcoin::{
        script::PushBytesBuf, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf, Transaction,
        XOnlyPublicKey,
    },
    descriptor,
    error::CreateTxError,
    KeychainKind, LocalOutput, TxOrdering, Wallet,
};
use sync::{Backend, SyncError};
use tokio::time::sleep;
use tracing::{error, info};

/// How many times we should reattempt after an error during a wallet sync
const SYNC_RETRIES: u32 = 5;
/// The wallet will delay a retry by SYNC_BASE_DELAY*SYNC_BACKOFF^current_retry,
/// exponential backoff
const SYNC_BACKOFF: u32 = 3;
const SYNC_BASE_DELAY: Duration = Duration::from_millis(100);

/// Config for [`OperatorWallet`]
#[derive(Debug)]
pub struct OperatorWalletConfig {
    /// Value of the funding UTXO for stakes. Not the `s` connector value.
    stake_funding_utxo_value: Amount,
    /// Value of CPFP UTXOs to identify them
    cpfp_value: Amount,
    /// Value of the `s` connector, the stake amount, to identify the UTXO
    s_value: Amount,
    /// Bitcoin network we're on
    network: Network,
}

impl OperatorWalletConfig {
    /// Creates a new [`OperatorWalletConfig`].
    ///
    /// # Panics
    ///
    /// Panics if `cpfp_value` == `s_value`
    pub fn new(
        stake_funding_utxo_value: Amount,
        cpfp_value: Amount,
        s_value: Amount,
        network: Network,
    ) -> Self {
        assert_ne!(
            cpfp_value, s_value,
            "the value of `s` cannot be the same as the CPFP value"
        );
        Self {
            stake_funding_utxo_value,
            cpfp_value,
            s_value,
            network,
        }
    }
}

/// The [`OperatorWallet`] is responsible for managing an operator's L1 funds, split into a general
/// wallet and a dedicated stakechain wallet.
#[derive(Debug)]
pub struct OperatorWallet {
    general_wallet: Wallet,
    stakechain_wallet: Wallet,
    config: OperatorWalletConfig,
    stakechain_addr_script_buf: ScriptBuf,
    general_addr_script_buf: ScriptBuf,
    sync_backend: Backend,
    leased_outpoints: BTreeSet<OutPoint>,
    /// The outpoints used to fund the withdrawal fulfillment transactions.
    ///
    /// This keeps track of all such utxos so that two parallel withdrawal fulfillment executors do
    /// not end up acquiring the same funding utxo and failing due to double-spend. It is assumed
    /// that the [`OperatorWallet`] itself is accessed via a mutually exclusive lock and so
    /// this [`BTreeSet`] is not behind another lock.
    fronting_outpoints: BTreeSet<OutPoint>,
}

impl OperatorWallet {
    /// Creates a new [`OperatorWallet`]
    pub fn new(
        general: XOnlyPublicKey,
        stakechain: XOnlyPublicKey,
        config: OperatorWalletConfig,
        sync_backend: Backend,
        leased_outpoints: BTreeSet<OutPoint>,
    ) -> Self {
        let (general_desc, ..) = descriptor!(tr(general)).unwrap();
        let (stakechain_desc, ..) = descriptor!(tr(stakechain)).unwrap();
        let general_wallet = Wallet::create_single(general_desc)
            .network(config.network)
            .create_wallet_no_persist()
            .unwrap();
        let general_addr = general_wallet
            .peek_address(KeychainKind::External, 0)
            .address;
        info!("general wallet address: {general_addr}");
        let stakechain_wallet = Wallet::create_single(stakechain_desc)
            .network(config.network)
            .create_wallet_no_persist()
            .unwrap();
        let stakechain_addr = stakechain_wallet
            .peek_address(KeychainKind::External, 0)
            .address;
        info!("stakechain wallet address: {stakechain_addr}");
        Self {
            config,
            stakechain_addr_script_buf: stakechain_addr.script_pubkey(),
            general_addr_script_buf: general_addr.script_pubkey(),
            general_wallet,
            stakechain_wallet,
            sync_backend,
            fronting_outpoints: BTreeSet::new(),
            leased_outpoints,
        }
    }

    /// Predicate for determining whether a utxo can be used as an anchor. This will only select
    /// unconfirmed minimum value outputs.
    fn is_anchor(&self, txout: &LocalOutput) -> bool {
        txout.txout.value == self.config.cpfp_value && !txout.chain_position.is_confirmed()
    }

    fn is_claim_funding_output(&self, txout: &LocalOutput) -> bool {
        txout.txout.value == self.config.stake_funding_utxo_value
    }

    /// Returns the list of known anchor outputs that should only be spent when fee bumping.
    pub fn anchor_outputs(&self) -> impl Iterator<Item = LocalOutput> + '_ {
        self.general_wallet
            .list_unspent()
            .filter(|utxo| self.is_anchor(utxo))
    }

    /// Returns the list of outputs that match the criteria for claim funding.
    pub fn claim_funding_outputs(&self) -> impl Iterator<Item = LocalOutput> + '_ {
        self.stakechain_wallet
            .list_unspent()
            .filter(|txout| self.is_claim_funding_output(txout))
    }

    /// Returns the list of [`OutPoint`]s that are currently being leased by the system.
    pub fn leased_outpoints(&self) -> impl Iterator<Item = OutPoint> + '_ {
        self.leased_outpoints.iter().copied()
    }

    /// Returns a list of UTXOs from the general wallet that can be used for fronting withdrawals.
    /// Excludes anchor outputs.
    pub fn general_utxos(&self) -> impl Iterator<Item = LocalOutput> + '_ {
        self.general_wallet
            .list_unspent()
            .filter(|utxo| !self.is_anchor(utxo))
    }

    fn lease(&mut self, outpoint: OutPoint) -> bool {
        self.leased_outpoints.insert(outpoint)
    }

    fn is_leased_pred<'a>(&'a self) -> impl Fn(&OutPoint) -> bool + 'a {
        |outpoint| self.leased_outpoints.contains(outpoint)
    }

    /// Creates a PSBT that outfronts a withdrawal from the general wallet to a user owned P2TR
    /// address. (excluding anchor outputs). Needs signing by the general wallet.
    ///
    /// # Notes
    ///
    /// The caller is responsible of assuring that the `OP_RETURN` data is within standard limits,
    /// i.e. `<= 80` bytes.
    ///
    /// This transaction is a version 3 transaction that supports 1-parent-1-child (1P1C) package
    /// relay mempool policies. The transaction maximum size is `10_000` virtual bytes.
    pub fn front_withdrawal(
        &mut self,
        fee_rate: FeeRate,
        user_script_pubkey: ScriptBuf,
        amount: Amount,
        op_return_data: &[u8],
    ) -> Result<Psbt, CreateTxError> {
        let mut push_data = PushBytesBuf::new();
        push_data
            .extend_from_slice(op_return_data)
            .expect("op_return_data should be within limit");
        let anchor_outpoints = self.anchor_outputs().map(|lo| lo.outpoint).collect();

        let mut tx_builder = self.general_wallet.build_tx();
        // Set transaction version to 3 for CPFP 1P1C TRUC transactions.
        tx_builder.version(3);
        // DON'T spend any of the anchor outputs
        tx_builder.unspendable(anchor_outpoints);
        tx_builder.unspendable(self.fronting_outpoints.iter().copied().collect());
        tx_builder.fee_rate(fee_rate);
        tx_builder.add_recipient(user_script_pubkey, amount);
        tx_builder.add_data(&push_data);
        tx_builder.ordering(TxOrdering::Untouched);

        let psbt = tx_builder.finish()?;

        // Mark the used input(s) as fronted so we can track it later
        psbt.unsigned_tx.input.iter().for_each(|input| {
            self.fronting_outpoints.insert(input.previous_output);
        });

        Ok(psbt)
    }

    /// Funds an unfunded version 3 transaction by adding inputs and change.
    ///
    /// Takes a transaction with outputs only and adds inputs from the general wallet to cover the
    /// outputs plus fees. Change, if any, is added at the end of vouts.
    ///
    /// The used UTXOs are marked as reserved so that two different executors do not end up using
    /// the same UTXOs and failing due to double-spend.
    ///
    /// # Notes
    ///
    /// This transaction is a version 3 transaction that supports 1-parent-1-child (1P1C) package
    /// relay mempool policies. The transaction maximum size is `10_000` virtual bytes.
    pub fn fund_v3_transaction(
        &mut self,
        unfunded_tx: Transaction,
        fee_rate: FeeRate,
    ) -> Result<Psbt, CreateTxError> {
        let anchor_outpoints = self.anchor_outputs().map(|lo| lo.outpoint).collect();

        let mut tx_builder = self.general_wallet.build_tx();
        // Set transaction version to 3 for CPFP 1P1C TRUC transactions.
        tx_builder.version(3);
        // DON'T spend any of the anchor outputs or already-used fronting outputs
        tx_builder.unspendable(anchor_outpoints);
        tx_builder.unspendable(self.fronting_outpoints.iter().copied().collect());
        tx_builder.fee_rate(fee_rate);

        // Add all outputs from the unfunded transaction
        for output in &unfunded_tx.output {
            tx_builder.add_recipient(output.script_pubkey.clone(), output.value);
        }

        tx_builder.ordering(TxOrdering::Untouched);

        let psbt = tx_builder.finish()?;

        // Mark the used input(s) as fronted so we can track it later
        psbt.unsigned_tx.input.iter().for_each(|input| {
            self.fronting_outpoints.insert(input.previous_output);
        });

        Ok(psbt)
    }

    /// Creates a PSBT that refills the pool of claim funding UTXOs from the general wallet
    /// (excluding anchor outputs). Needs signing by the general wallet.
    ///
    /// # Notes
    ///
    /// This transaction is a version 3 transaction that supports 1-parent-1-child (1P1C) package
    /// relay mempool policies. The transaction maximum size is `10_000` virtual bytes.
    pub fn refill_claim_funding_utxos(
        &mut self,
        fee_rate: FeeRate,
        target_size: usize,
    ) -> Result<Psbt, CreateTxError> {
        let current_claim_funding_outpoints: Vec<OutPoint> = self
            .claim_funding_outputs()
            .map(|o| o.outpoint)
            .filter(predicate::not(self.is_leased_pred()))
            .collect();

        let anchor_outpoints = self.anchor_outputs().map(|lo| lo.outpoint);
        let leased_outpoints = self.leased_outpoints();

        // DON'T spend any of the anchor outputs or the existing claim funding utxos or
        // anything leased.
        let excluded = current_claim_funding_outpoints
            .iter()
            .copied()
            .chain(anchor_outpoints)
            .chain(leased_outpoints)
            .collect();

        let mut tx_builder = self.general_wallet.build_tx();
        // Set transaction version to 3 for CPFP 1P1C TRUC transactions.
        tx_builder.version(3);
        tx_builder.unspendable(excluded);

        let current_size = current_claim_funding_outpoints.len();
        let batch_size = target_size - current_size;
        for _ in 0..batch_size {
            tx_builder.add_recipient(
                self.stakechain_addr_script_buf.clone(),
                self.config.stake_funding_utxo_value,
            );
        }

        tx_builder.fee_rate(fee_rate);

        tx_builder.finish()
    }

    /// Attempts to find a funding UTXO for a stake, ignoring outpoints for which ignore returns
    /// `true`. The first value returned is the assigned claim funding output if one is found. The
    /// second value returned is the remaining number of claim funding outputs excluding the one
    /// in the first return value.
    pub fn claim_funding_utxo(
        &mut self,
        ignore: impl Fn(&OutPoint) -> bool,
    ) -> (Option<OutPoint>, u64) {
        let ignore_leased = |o: &OutPoint| self.leased_outpoints.contains(o);
        let consider = predicate::contramap(
            |o: &LocalOutput| o.outpoint,
            predicate::nor(ignore, ignore_leased),
        );

        let mut considered = self.claim_funding_outputs().filter(consider);
        let claim_funding_output = considered.next().map(|utxo| utxo.outpoint);
        let remaining = considered.count() as u64;

        let leased = claim_funding_output.and_then(predicate::guard_mut(|o| self.lease(*o)));

        (leased, remaining)
    }

    /// Tries to find the `s` connector UTXO from the prestake transaction
    pub fn s_utxo(&self) -> Option<LocalOutput> {
        self.stakechain_wallet
            .list_unspent()
            .find(|utxo| utxo.txout.value == self.config.s_value)
    }

    /// Creates a new prestake transaction by paying funds from the general wallet into the
    /// stakechain wallet (excludes anchor outputs). This will create a [Self::s_utxo].
    ///
    /// # Notes
    ///
    /// This transaction is a version 3 transaction that supports 1-parent-1-child (1P1C) package
    /// relay mempool policies. The transaction maximum size is `10_000` virtual bytes.
    pub fn create_prestake_tx(&mut self, fee_rate: FeeRate) -> Result<Psbt, CreateTxError> {
        let anchor_outpoints = self.anchor_outputs().map(|lo| lo.outpoint).collect();
        let mut tx_builder = self.general_wallet.build_tx();
        // Set transaction version to 3 for CPFP 1P1C TRUC transactions.
        tx_builder.version(3);
        // DON'T spend any of the anchor outputs
        tx_builder.unspendable(anchor_outpoints);
        tx_builder.fee_rate(fee_rate);
        tx_builder.add_recipient(self.stakechain_addr_script_buf.clone(), self.config.s_value);
        tx_builder.ordering(TxOrdering::Untouched);
        tx_builder.finish()
    }

    /// Returns the script buf of the general wallet address. External funds should be sent here.
    pub const fn general_script_buf(&self) -> &ScriptBuf {
        &self.general_addr_script_buf
    }

    /// Returns the script buf of the stake chain wallet address.
    ///
    /// This is where the reserved funds for funding dust outputs reside.
    pub const fn stakechain_script_buf(&self) -> &ScriptBuf {
        &self.stakechain_addr_script_buf
    }

    /// Returns an immutable reference to the general wallet
    pub const fn general_wallet(&self) -> &Wallet {
        &self.general_wallet
    }

    /// Returns an immutable reference to the stakechain wallet
    pub const fn stakechain_wallet(&self) -> &Wallet {
        &self.stakechain_wallet
    }

    /// Syncs the wallet using the backend provided on construction.
    pub async fn sync(&mut self) -> Result<(), SyncError> {
        let mut attempt = 0;
        loop {
            let mut err = None;
            if let Err(e) = self
                .sync_backend
                .sync_wallet(&mut self.general_wallet, &mut self.leased_outpoints)
                .await
            {
                err = Some(e);
            }
            if let Err(e) = self
                .sync_backend
                .sync_wallet(&mut self.stakechain_wallet, &mut self.leased_outpoints)
                .await
            {
                err = Some(e);
            }

            match err {
                Some(e) => {
                    error!(?e, "error syncing wallet");
                    if attempt >= SYNC_RETRIES {
                        break Err(e);
                    }
                    sleep(SYNC_BASE_DELAY * SYNC_BACKOFF.pow(attempt)).await;
                    attempt += 1;
                }
                None => break Ok(()),
            }
        }
    }
}
