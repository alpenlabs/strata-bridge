use bitcoin::{sighash::Prevouts, Amount, Psbt, TxOut, Txid};
use strata_bridge_primitives::scripts::taproot::TaprootWitness;

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
}
