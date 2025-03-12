//! Operator wallet
pub mod sync;

use bdk_wallet::{
    bitcoin::{Amount, FeeRate, Network, Psbt, ScriptBuf, XOnlyPublicKey},
    descriptor,
    error::CreateTxError,
    KeychainKind, LocalOutput, Wallet,
};
use sync::{Backend, SyncError};
use tracing::{debug, info};

/// Config for [OperatorWallet]
#[derive(Debug)]
pub struct OperatorWalletConfig {
    /// Value of the funding UTXO for stakes. Not `s`.
    stake_funding_utxo_value: Amount,
    /// Number of UTXOs of amount claim_funding_utxo_value sat to keep on hand at minimum
    stake_funding_utxo_pool_size: usize,
    /// Value of CPFP UTXOs to identify them
    cpfp_value: Amount,
    /// Value of `s`, the stake amount, to identify the UTXO
    s_value: Amount,
}

const NETWORK: Network = Network::Signet;

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
    pub fn new(
        general: XOnlyPublicKey,
        stakechain: XOnlyPublicKey,
        config: OperatorWalletConfig,
        sync_backend: Backend,
    ) -> Self {
        let (general_desc, ..) = descriptor!(tr(general)).unwrap();
        let (stakechain_desc, ..) = descriptor!(tr(stakechain)).unwrap();
        let general_wallet = Wallet::create_single(general_desc)
            .network(NETWORK)
            .create_wallet_no_persist()
            .unwrap();
        let general_addr = general_wallet
            .peek_address(KeychainKind::External, 0)
            .address;
        info!("general wallet address: {general_addr}");
        let stakechain_wallet = Wallet::create_single(stakechain_desc)
            .network(NETWORK)
            .create_wallet_no_persist()
            .unwrap();
        let stakechain_addr = stakechain_wallet
            .peek_address(KeychainKind::External, 0)
            .address;
        info!("stakechain wallet address: {stakechain_addr}");
        Self {
            config,
            stakechain_addr_script_buf: stakechain_wallet
                .peek_address(KeychainKind::External, 0)
                .address
                .script_pubkey(),
            general_addr_script_buf: general_wallet
                .peek_address(KeychainKind::External, 0)
                .address
                .script_pubkey(),
            general_wallet,
            stakechain_wallet,
            sync_backend,
        }
    }

    // /// Tries to find a UTXO for a new stake
    // pub fn get_stake_funding_utxo(&mut self) -> MaybeStakeFundingUtxo {
    //     let mut available_utxos = self
    //         .stakechain_wallet
    //         .list_unspent()
    //         .filter(|utxo| utxo.txout.value == self.config.stake_funding_utxo_value)
    //         .collect::<Vec<_>>();
    //     debug!(
    //         "found {} available utxos to fund a new stake",
    //         available_utxos.len()
    //     );

    //     match available_utxos.len() {
    //         0 => MaybeStakeFundingUtxo::Empty,
    //         n if n < self.config.stake_funding_utxo_pool_size => {
    //             debug!("only have {n} available left");
    //             MaybeStakeFundingUtxo::NeedsRefill(available_utxos.pop().unwrap())
    //         }
    //         _ => MaybeStakeFundingUtxo::Available(available_utxos.pop().unwrap()),
    //     }
    // }

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

    /// Tries to find the `s` UTXO from the prestake transaction
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
        tx_builder.finish()
    }

    /// Returns the script buf of the general wallet address. External funds should be sent here.
    pub fn general_script_buf(&self) -> &ScriptBuf {
        &self.general_addr_script_buf
    }

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

pub enum MaybeStakeFundingUtxo {
    /// We found a UTXO that can be used for a new stake
    Available(LocalOutput),
    /// We found a UTXO that can be used for a new stake, BUT we're running out
    /// and you should refill via [OperatorWallet::refill_claim_funding_utxos]
    NeedsRefill(LocalOutput),
    /// There aren't any UTXOs to use to fund a stake.
    Empty,
}
