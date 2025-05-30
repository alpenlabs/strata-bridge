//! Trait for transactions in the tx graph that require N-of-N signatures to emulate covenants.

use bitcoin::{
    sighash::{Prevouts, SighashCache},
    Amount, Psbt, TapSighashType, TxOut, Txid,
};
use secp256k1::Message;
use strata_bridge_primitives::scripts::taproot::{create_message_hash, TaprootWitness};

/// A trait for transactions in the tx graph that require N-of-N signatures to emulate covenants.
pub trait CovenantTx<const NUM_COVENANT_INPUTS: usize> {
    /// Gets the PSBT.
    fn psbt(&self) -> &Psbt;

    /// Gets a mutable reference to the PSBT.
    fn psbt_mut(&mut self) -> &mut Psbt;

    /// Gets the prevouts that the transaction spends.
    fn prevouts(&self) -> Prevouts<'_, TxOut>;

    /// Gets the witnesses required to spend the transaction.
    fn witnesses(&self) -> &[TaprootWitness; NUM_COVENANT_INPUTS];

    /// Get the total input amount of the transaction.
    fn input_amount(&self) -> Amount;

    /// Computes the transaction ID.
    fn compute_txid(&self) -> Txid;

    /// Gets the sighash type for each input in the transaction.
    fn sighash_types(&self) -> [TapSighashType; NUM_COVENANT_INPUTS] {
        self.psbt()
            .inputs
            .get(..NUM_COVENANT_INPUTS)
            .expect("must have enough inputs")
            .iter()
            .map(|input| {
                input
                    .sighash_type
                    .map(|sighash_type| sighash_type.taproot_hash_ty())
                    .unwrap_or(Ok(TapSighashType::Default))
                    .unwrap()
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("must have the right number of inputs")
    }

    /// Computes the sighash of the transaction per input.
    ///
    /// # Panics
    ///
    /// If the number of inputs in the transaction is less than `NUM_COVENANT_INPUTS`.
    fn sighashes(&self) -> [Message; NUM_COVENANT_INPUTS] {
        let tx = &self.psbt().unsigned_tx;
        let mut sighash_cache = SighashCache::new(tx);
        let prevouts = self.prevouts();

        self.sighash_types()
            .into_iter()
            .zip(self.witnesses())
            .enumerate()
            .map(|(input_index, (sighash_type, witness_type))| {
                create_message_hash(
                    &mut sighash_cache,
                    prevouts.clone(),
                    witness_type,
                    sighash_type,
                    input_index,
                )
                .expect("must be able to create message hash")
            })
            .collect::<Vec<_>>()
            .try_into()
            .expect("must have the right number of inputs")
    }
}
