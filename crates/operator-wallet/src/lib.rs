//! Operator wallet
pub mod sync;

use bdk_wallet::{
    bitcoin::{
        script::PushBytesBuf, Address, AddressType, Amount, FeeRate, Network, OutPoint, Psbt,
        ScriptBuf, XOnlyPublicKey,
    },
    descriptor,
    error::CreateTxError,
    KeychainKind, LocalOutput, TxOrdering, Wallet,
};
use sync::{Backend, SyncError};
use tracing::{debug, info};

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
        }
    }

    /// Returns the list of known CPFP outputs that should only be spent when fee bumping
    pub fn cpfp_utxos(&self) -> Vec<LocalOutput> {
        let v = self
            .general_wallet
            .list_unspent()
            .filter(|utxo| utxo.txout.value == self.config.cpfp_value)
            .collect::<Vec<_>>();
        debug!("found {} CPFP UTXOs", v.len());
        v
    }

    /// Returns a list of UTXOs from the general wallet that can be used for fronting withdrawals.
    /// Excludes CPFP outputs.
    pub fn general_utxos(&self) -> Vec<LocalOutput> {
        let v = self
            .general_wallet
            .list_unspent()
            .filter(|utxo| utxo.txout.value != self.config.cpfp_value)
            .collect::<Vec<_>>();
        debug!("found {} non-CPFP UTXOs", v.len());
        v
    }

    /// Creates a PSBT that outfronts a withdrawal from the general wallet to a user owned P2TR
    /// address. (excluding CPFP outputs). Needs signing by the general wallet.
    ///
    /// The caller is responsible of assuring that the `OP_RETURN` data is within standard limits,
    /// i.e. `<= 80` bytes.
    pub fn front_withdrawal(
        &mut self,
        fee_rate: FeeRate,
        user_p2tr_address: Address,
        amount: Amount,
        op_return_data: &[u8],
    ) -> Result<Psbt, CreateTxError> {
        if user_p2tr_address.address_type() != Some(AddressType::P2tr) {
            return Err(CreateTxError::NoRecipients);
        }
        let mut push_data = PushBytesBuf::new();
        push_data
            .extend_from_slice(op_return_data)
            .expect("op_return_data should be within limit");
        let cpfp_utxos = self
            .cpfp_utxos()
            .into_iter()
            .map(|lo| lo.outpoint)
            .collect();
        let mut tx_builder = self.general_wallet.build_tx();
        // DON'T spend any of the cpfp outputs
        tx_builder.unspendable(cpfp_utxos);
        tx_builder.fee_rate(fee_rate);
        tx_builder.add_recipient(user_p2tr_address.script_pubkey(), amount);
        tx_builder.add_data(&push_data);
        tx_builder.finish()
    }

    /// Creates a PSBT that refills the pool of claim funding UTXOs from the general wallet
    /// (excluding CPFP outputs). Needs signing by the general wallet.
    pub fn refill_claim_funding_utxos(&mut self, fee_rate: FeeRate) -> Result<Psbt, CreateTxError> {
        let cpfp_utxos = self
            .cpfp_utxos()
            .into_iter()
            .map(|lo| lo.outpoint)
            .collect();
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
    pub fn claim_funding_utxo(&self, ignore: impl Fn(OutPoint) -> bool) -> FundingUtxo {
        let mut utxos = self
            .stakechain_wallet
            .list_unspent()
            .filter(|utxo| {
                !ignore(utxo.outpoint) && utxo.txout.value == self.config.stake_funding_utxo_value
            })
            .collect::<Vec<_>>();
        if utxos.is_empty() {
            FundingUtxo::Empty
        } else if utxos.len() < self.config.stake_funding_utxo_pool_size {
            FundingUtxo::ShouldRefill {
                op: utxos.pop().unwrap().outpoint,
                left: utxos.len(),
            }
        } else {
            FundingUtxo::Available(utxos.pop().unwrap().outpoint)
        }
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
        let cpfp_utxos = self
            .cpfp_utxos()
            .into_iter()
            .map(|lo| lo.outpoint)
            .collect();
        let mut tx_builder = self.general_wallet.build_tx();
        // DON'T spend any of the cpfp outputs
        tx_builder.unspendable(cpfp_utxos);
        tx_builder.fee_rate(fee_rate);
        tx_builder.add_recipient(self.stakechain_addr_script_buf.clone(), self.config.s_value);
        tx_builder.ordering(TxOrdering::Untouched);
        tx_builder.finish()
    }

    /// Returns the script buf of the general wallet address. External funds should be sent here.
    pub fn general_script_buf(&self) -> &ScriptBuf {
        &self.general_addr_script_buf
    }

    /// Returns an immutable reference to the general wallet
    pub fn general_wallet(&self) -> &Wallet {
        &self.general_wallet
    }

    /// Returns an immutable reference to the stakechain wallet
    pub fn stakechain_wallet(&self) -> &Wallet {
        &self.stakechain_wallet
    }

    /// Syncs the wallet using the backend provided on construction
    pub async fn sync(&mut self) -> Result<(), SyncError> {
        self.sync_backend
            .sync_wallet(&mut self.general_wallet)
            .await?;
        self.sync_backend
            .sync_wallet(&mut self.stakechain_wallet)
            .await?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
/// Represents the wallet suggesting a specific UTXO
pub enum FundingUtxo {
    /// The wallet found a UTXO that can be used for funding
    Available(OutPoint),
    /// The wallet found a UTXO that can be used for funding, but also needs you to perform a
    /// refill
    ShouldRefill {
        /// Funding outpoint
        op: OutPoint,
        /// How many funding utxos we have left
        left: usize,
    },
    /// Really bad if this happens because you should've refilled when we told you too.
    Empty,
}
