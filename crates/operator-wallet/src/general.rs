//! The operator's general-purpose funds: the wallet that fronts payments, pays CPFP fees, and tops
//! up other internal pools.
//!
//! Both custody choices track their script on the operator's own node through one
//! [`TrackedWallet`](crate::TrackedWallet), so the composer [`crate::OperatorWallet`] reads one
//! chain view whoever signs. Custody decides only the script, the size of a signed input, and who
//! signs. Leases, the reserved wallet, input selection, and transaction construction live on the
//! composer.

#[cfg(feature = "fireblocks")]
pub mod fireblocks;

use bdk_wallet::{
    bitcoin::{transaction::InputWeightPrediction, Transaction, TxOut, Witness, XOnlyPublicKey},
    descriptor,
    descriptor::ExtendedDescriptor,
};

#[cfg(feature = "fireblocks")]
use self::fireblocks::{CheckedVault, FireblocksSigner};

/// Who holds the keys of the general funds, and the store of the wallet that tracks them.
///
/// [`OperatorWallet::load_or_create`](crate::OperatorWallet::load_or_create) takes the tracked
/// script and the signer from this one value, so a wallet cannot track one script and sign for
/// another.
#[derive(Debug)]
pub enum GeneralCustody<P> {
    /// Keys in secret-service. The wallet tracks `tr(general_key)`.
    ///
    /// Payouts arrive at the BIP-341 tweaked general key, so they are ordinary wallet UTXOs and
    /// the tap-tweaking signer in secret-service can spend them.
    SecretService {
        /// The untweaked general key.
        general_key: XOnlyPublicKey,
        /// The store of the tracked wallet.
        store: P,
    },
    /// Keys in a Fireblocks vault. The value proves that the startup check ran against this store.
    #[cfg(feature = "fireblocks")]
    Fireblocks(CheckedVault<P>),
}

impl<P> GeneralCustody<P> {
    /// Splits the value into the descriptor to track, the signer of that descriptor, and the store
    /// of the tracked wallet.
    pub(crate) fn into_parts(self) -> (ExtendedDescriptor, GeneralSigner, P) {
        match self {
            Self::SecretService { general_key, store } => {
                let (descriptor, ..) = descriptor!(tr(general_key)).expect("valid tr() descriptor");
                (descriptor, GeneralSigner::SecretService, store)
            }
            #[cfg(feature = "fireblocks")]
            Self::Fireblocks(vault) => {
                let (descriptor, signer, store) = vault.into_parts();
                (descriptor, GeneralSigner::Fireblocks(signer), store)
            }
        }
    }
}

/// The error of a failed [`GeneralSigner::sign_owned_inputs`]. Only a vault can fail, because
/// secret-service signs downstream of this type. A caller logs the error and retries, so it needs
/// no variants, and the type stays the same with or without the `fireblocks` feature.
pub type GeneralSignError = Box<dyn std::error::Error + Send + Sync>;

/// Signs inputs that spend the general funds.
///
/// A signer can wait on an external service for minutes. It is a separate handle so that a caller
/// holds no wallet lock during that wait: the caller takes the handle under the lock, releases
/// the lock, and then signs.
#[derive(Debug, Clone)]
pub enum GeneralSigner {
    /// Keys in secret-service. This value holds no key material, so the caller signs every input
    /// downstream.
    SecretService,
    /// Keys in a Fireblocks vault. It signs through the Fireblocks API.
    #[cfg(feature = "fireblocks")]
    Fireblocks(FireblocksSigner),
}

impl GeneralSigner {
    /// Size of one signed input that spends the general funds. The fee of a transaction that the
    /// composer plans depends on it.
    pub const fn input_prediction(&self) -> InputWeightPrediction {
        match self {
            Self::SecretService => InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH,
            #[cfg(feature = "fireblocks")]
            Self::Fireblocks(_) => InputWeightPrediction::P2WPKH_MAX,
        }
    }

    /// Signs the inputs of `tx` at `input_indices`.
    ///
    /// Returns one entry per index: a witness for an input that this signer holds a key for, or
    /// `None` for an input that the caller must sign downstream.
    /// [`SecretService`](Self::SecretService) returns `None` for every index.
    ///
    /// `prevouts[i]` must be the output spent by `tx.input[i]`, for every input of `tx`.
    ///
    /// A later attempt signs afresh, so a caller treats every error as transient.
    #[cfg_attr(not(feature = "fireblocks"), allow(unused_variables))]
    pub async fn sign_owned_inputs(
        &self,
        tx: &Transaction,
        input_indices: &[usize],
        prevouts: &[TxOut],
    ) -> Result<Vec<Option<Witness>>, GeneralSignError> {
        match self {
            Self::SecretService => Ok(vec![None; input_indices.len()]),
            #[cfg(feature = "fireblocks")]
            Self::Fireblocks(signer) => signer
                .sign_owned_inputs(tx, input_indices, prevouts)
                .await
                .map_err(Into::into),
        }
    }
}
