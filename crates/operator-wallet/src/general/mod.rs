//! The operator's general-purpose funds: the wallet that fronts payments, pays CPFP fees, and tops
//! up other internal pools.
//!
//! The custody tracks its script on the operator's own node through one
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
