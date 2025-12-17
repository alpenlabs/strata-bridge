//! This module contains the individual transactions of the Glock transaction graph.

use bitcoin::{psbt::Psbt, sighash::SighashCache, OutPoint, Transaction, TxOut};
use secp256k1::schnorr;

use crate::connectors::SigningInfo;

pub mod claim;
pub mod prelude;

/// Bitcoin transaction that is the parent in a CPFP fee-bumping scheme.
pub trait ParentTx {
    /// Returns the output that is spent by the CPFP child.
    fn cpfp_tx_out(&self) -> TxOut;

    /// Returns the outpoint that is spent by the CPFP child.
    fn cpfp_outpoint(&self) -> OutPoint;
}

/// Bitcoin transaction that spends an N/N output.
///
/// `N_INPUTS` is the number of transaction inputs.
/// A presigned transaction has an N/N spending condition in each of its inputs.
pub trait PresignedTx<const N_INPUTS: usize> {
    // NOTE: (@uncomputable) ExtraWitness will be empty for most transactions.
    // This is annoying because `finalize()` is called with an `&()` argument.
    // We could implement an extension trait if we feel like it.
    /// Witness data that is required to finalize the transaction,
    /// excluding N/N signatures.
    type ExtraWitness;

    /// Gets the PSBT.
    fn psbt(&self) -> &Psbt;

    /// Get the signing info for each transaction input.
    fn signing_info(&self) -> [SigningInfo; N_INPUTS] {
        let mut cache = SighashCache::new(&self.psbt().unsigned_tx);
        std::array::from_fn(|i| self.get_signing_info(&mut cache, i))
    }

    /// Get the signing info for the transaction input at the given index.
    ///
    /// # Panics
    ///
    /// This method panics if the input index is out of bounds.
    fn get_signing_info(
        &self,
        cache: &mut SighashCache<&Transaction>,
        input_index: usize,
    ) -> SigningInfo;

    /// Finalizes the transaction with the given witness data.
    ///
    /// The witness consists of N/N signatures and of extra data.
    /// The order of N/N signatures must match the order of signing infos from
    /// [`Self::each_signing_info()]`.
    fn finalize(
        self,
        n_of_n_signatures: [schnorr::Signature; N_INPUTS],
        extra: &Self::ExtraWitness,
    ) -> Transaction;
}
