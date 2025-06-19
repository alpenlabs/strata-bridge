//! Operator wallet
pub mod sync;

use std::collections::BTreeSet;

use algebra::predicate;
use bdk_wallet::{
    bitcoin::{
        script::PushBytesBuf, Amount, FeeRate, Network, OutPoint, Psbt, ScriptBuf, XOnlyPublicKey,
    },
    descriptor,
    error::CreateTxError,
    KeychainKind, LocalOutput, TxOrdering, Wallet,
};
use sync::{Backend, SyncError};
use tracing::info;

/// Config for [`OperatorWallet`]
#[derive(Debug)]
pub struct OperatorWalletConfig {
    /// Value of the funding UTXO for stakes. Not the `s` connector value.
    stake_funding_utxo_value: Amount,
    /// Number of UTXOs of amount claim_funding_utxo_value sat to keep on hand at minimum
    stake_funding_utxo_pool_size: usize,
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
        stake_funding_utxo_pool_size: usize,
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
            stake_funding_utxo_pool_size,
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
}

impl OperatorWallet {
    /// Creates a new [`OperatorWallet`]
    pub fn new(
        general: XOnlyPublicKey,
        stakechain: XOnlyPublicKey,
        config: OperatorWalletConfig,
        sync_backend: Backend,
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
            leased_outpoints: BTreeSet::new(),
        }
    }

    fn is_anchor(&self, txout: &LocalOutput) -> bool {
        txout.txout.value == self.config.cpfp_value && !txout.chain_position.is_confirmed()
    }

    fn is_claim_funding_output(&self, txout: &LocalOutput) -> bool {
        txout.txout.value == self.config.stake_funding_utxo_value
    }

    /// Returns the list of known anchor outputs that should only be spent when fee bumping
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

    /// Returns a list of UTXOs from the general wallet that can be used for fronting withdrawals.
    /// Excludes CPFP outputs.
    pub fn general_utxos(&self) -> impl Iterator<Item = LocalOutput> + '_ {
        self.general_wallet
            .list_unspent()
            .filter(|utxo| !self.is_anchor(utxo))
    }

    fn lease(&mut self, outpoint: OutPoint) -> Result<(), CreateTxError> {
        if self.leased_outpoints.contains(&outpoint) {
            Err(CreateTxError::UnknownUtxo)
        } else {
            self.leased_outpoints.insert(outpoint);
            Ok(())
        }
    }

    /// Creates a PSBT that outfronts a withdrawal from the general wallet to a user owned P2TR
    /// address. (excluding CPFP outputs). Needs signing by the general wallet.
    ///
    /// The caller is responsible of assuring that the `OP_RETURN` data is within standard limits,
    /// i.e. `<= 80` bytes.
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
        let cpfp_utxos = self.anchor_outputs().map(|lo| lo.outpoint).collect();

        let mut tx_builder = self.general_wallet.build_tx();
        // DON'T spend any of the cpfp outputs
        tx_builder.unspendable(cpfp_utxos);
        tx_builder.fee_rate(fee_rate);
        tx_builder.add_recipient(user_script_pubkey, amount);
        tx_builder.add_data(&push_data);
        tx_builder.ordering(TxOrdering::Untouched);
        tx_builder.finish()
    }

    /// Creates a PSBT that refills the pool of claim funding UTXOs from the general wallet
    /// (excluding CPFP outputs). Needs signing by the general wallet.
    pub fn refill_claim_funding_utxos(&mut self, fee_rate: FeeRate) -> Result<Psbt, CreateTxError> {
        let cpfp_utxos = self.anchor_outputs().map(|lo| lo.outpoint).collect();
        let mut tx_builder = self.general_wallet.build_tx();
        // DON'T spend any of the cpfp outputs
        tx_builder.unspendable(cpfp_utxos);
        tx_builder.fee_rate(fee_rate);
        for _ in 0..self.config.stake_funding_utxo_pool_size {
            tx_builder.add_recipient(
                self.stakechain_addr_script_buf.clone(),
                self.config.stake_funding_utxo_value,
            );
        }
        tx_builder.finish()
    }

    /// Attempts to find a funding UTXO for a stake, ignoring outpoints for which ignore returns
    /// `true`
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

        if let Some(o) = &claim_funding_output {
            self.lease(*o)
                .expect("must be able to lease claim funding output");
        }

        (claim_funding_output, remaining)
    }

    /// Tries to find the `s` connector UTXO from the prestake transaction
    pub fn s_utxo(&self) -> Option<LocalOutput> {
        self.stakechain_wallet
            .list_unspent()
            .find(|utxo| utxo.txout.value == self.config.s_value)
    }

    /// Creates a new prestake transaction by paying funds from the general wallet into the
    /// stakechain wallet (excludes CPFP outputs). This will create a [Self::s_utxo].
    pub fn create_prestake_tx(&mut self, fee_rate: FeeRate) -> Result<Psbt, CreateTxError> {
        let cpfp_utxos = self.anchor_outputs().map(|lo| lo.outpoint).collect();
        let mut tx_builder = self.general_wallet.build_tx();
        // DON'T spend any of the cpfp outputs
        tx_builder.unspendable(cpfp_utxos);
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

    /// Syncs the wallet using the backend provided on construction
    pub async fn sync(&mut self) -> Result<(), SyncError> {
        self.sync_backend
            .sync_wallet(&mut self.general_wallet, &mut self.leased_outpoints)
            .await?;
        self.sync_backend
            .sync_wallet(&mut self.stakechain_wallet, &mut self.leased_outpoints)
            .await?;
        Ok(())
    }
}
