use bitcoin::{
    psbt::PsbtSighashType, sighash::Prevouts, Amount, Network, OutPoint, Psbt, TapSighashType,
    Transaction, TxOut, Txid,
};
use secp256k1::schnorr;
use strata_bridge_primitives::{params::prelude::UNSPENDABLE_INTERNAL_KEY, scripts::prelude::*};

use super::covenant_tx::CovenantTx;
use crate::connectors::prelude::*;

/// Data needed to construct a [`DisproveTx`].
#[derive(Debug, Clone)]
pub struct DisproveData {
    /// The transaction ID of the post-assert transaction.
    pub post_assert_txid: Txid,

    /// The transaction ID of the deposit transaction.
    pub deposit_txid: Txid,

    /// The stake that remains after paying off the transaction fees in the preceding transactions.
    pub input_stake: Amount,

    /// The bitcoin network on which the transaction is to be constructed.
    pub network: Network,
}

/// The transaction used to disprove an operator's claim and slash their stake.
#[derive(Debug, Clone)]
pub struct DisproveTx {
    psbt: Psbt,

    prevouts: Vec<TxOut>,

    witnesses: Vec<TaprootWitness>,
}

impl DisproveTx {
    /// Constructs a new instance of the disprove transaction.
    pub fn new(
        data: DisproveData,
        connector_a30: ConnectorA30,
        connector_a31: ConnectorA31,
    ) -> Self {
        let utxos = [
            OutPoint {
                txid: data.post_assert_txid,
                vout: 0,
            },
            OutPoint {
                txid: data.post_assert_txid,
                vout: 1,
            },
        ];

        let tx_ins = create_tx_ins(utxos);

        let (burn_address, _) = create_taproot_addr(
            &data.network,
            SpendPath::KeySpend {
                internal_key: *UNSPENDABLE_INTERNAL_KEY,
            },
        )
        .expect("should be able to create taproot address");
        let burn_script = burn_address.script_pubkey();
        let burn_amount = burn_script.minimal_non_dust();

        let tx_outs = create_tx_outs([(burn_script, burn_amount)]);

        let tx = create_tx(tx_ins, tx_outs);

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("should be able to create psbt");

        let connector_a31_script = connector_a31.generate_locking_script(data.deposit_txid);
        let connector_a31_value = connector_a31_script.minimal_non_dust();

        let prevouts = vec![
            TxOut {
                value: data.input_stake,
                script_pubkey: connector_a30.generate_locking_script(),
            },
            TxOut {
                value: connector_a31_value,
                script_pubkey: connector_a31_script,
            },
        ];

        let (script_buf, control_block) =
            connector_a30.generate_spend_info(ConnectorA30Leaf::Disprove(()));
        let witness = TaprootWitness::Script {
            script_buf,
            control_block,
        };

        let witnesses = vec![witness];

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
        }

        psbt.inputs[0].sighash_type = Some(PsbtSighashType::from(TapSighashType::Single));

        Self {
            psbt,

            prevouts,
            witnesses,
        }
    }

    /// Finalizes the disprove transaction by adding the required witness and output data.
    pub fn finalize(
        mut self,
        connector_a30: ConnectorA30,
        connector_a31: ConnectorA31,
        reward: TxOut,
        deposit_txid: Txid,
        disprove_leaf: ConnectorA31Leaf,
        n_of_n_sig: schnorr::Signature,
    ) -> Transaction {
        connector_a30.finalize_input(
            &mut self.psbt.inputs[0],
            ConnectorA30Leaf::Disprove(n_of_n_sig),
        );

        connector_a31.finalize_input(&mut self.psbt.inputs[1], disprove_leaf, deposit_txid);

        let mut tx = self
            .psbt
            .extract_tx()
            .expect("should be able to extract tx");

        tx.output.push(reward);

        tx
    }
}

impl CovenantTx for DisproveTx {
    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    fn prevouts(&self) -> Prevouts<'_, TxOut> {
        Prevouts::All(&self.prevouts)
    }

    fn witnesses(&self) -> &[TaprootWitness] {
        &self.witnesses
    }

    fn compute_txid(&self) -> Txid {
        self.psbt.unsigned_tx.compute_txid()
    }

    fn input_amount(&self) -> Amount {
        self.psbt
            .inputs
            .iter()
            .map(|input| {
                input
                    .witness_utxo
                    .as_ref()
                    .expect("should have witness utxo")
                    .value
            })
            .sum()
    }
}
