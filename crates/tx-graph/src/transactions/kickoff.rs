use bitcoin::{Amount, OutPoint, Psbt, Transaction, TxOut, Txid};
use serde::{Deserialize, Serialize};
use strata_bridge_connectors::prelude::*;
use strata_bridge_primitives::{
    bitcoin::BitcoinAddress, errors::BridgeTxBuilderError, params::prelude::*, scripts::prelude::*,
};

use super::errors::TxResult;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KickoffTxData {
    pub funding_inputs: Vec<OutPoint>,
    pub funding_utxos: Vec<TxOut>,
    pub change_address: BitcoinAddress,
    pub change_amt: Amount,
    pub deposit_txid: Txid,
}

/// KickOff is just a wrapper around a Psbt.
///
/// One output of this Psbt is fixed but the other inputs and outputs can be variable so long as the
/// transaction itself is a SegWit transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KickOffTx(Psbt);

impl KickOffTx {
    /// Constructs a new instance of the kickoff transaction.
    pub fn new(data: KickoffTxData, connector_k: ConnectorK) -> TxResult<Self> {
        let tx_ins = create_tx_ins(data.funding_inputs);

        let commitment_script = connector_k.create_taproot_address().script_pubkey();

        let change_address = data.change_address.address();
        let scripts_and_amounts = [
            (commitment_script, OPERATOR_STAKE),
            (change_address.script_pubkey(), data.change_amt),
        ];

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let tx = create_tx(tx_ins, tx_outs);

        let mut psbt = Psbt::from_unsigned_tx(tx)
            .map_err(|e| BridgeTxBuilderError::PsbtCreate(e.to_string()))?;

        for (input, utxo) in psbt.inputs.iter_mut().zip(data.funding_utxos) {
            input.witness_utxo = Some(utxo);
        }

        Ok(Self(psbt))
    }

    /// Gets the underlying Psbt.
    pub fn psbt(&self) -> &Psbt {
        &self.0
    }

    /// Gets a mutable reference to the underlying Psbt.
    pub fn mut_psbt(&mut self) -> &mut Psbt {
        &mut self.0
    }

    /// Computes the transaction ID of the underlying transaction.
    pub fn compute_txid(&self) -> Txid {
        self.0.unsigned_tx.compute_txid()
    }

    /// Finalizes the transaction by signing it with the wallet.
    ///
    /// # Warning
    ///
    /// This is unimplemented.
    pub fn finalize(&self /* , signer: Signer */) -> Transaction {
        unimplemented!("implement signing with bitcoin wallet");
    }
}
