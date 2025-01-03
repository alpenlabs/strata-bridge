use bitcoin::{
    psbt::PsbtSighashType, sighash::Prevouts, Amount, Network, OutPoint, Psbt, TapSighashType,
    Transaction, TxOut, Txid,
};
use strata_bridge_db::public::PublicDb;
use strata_bridge_primitives::{
    params::prelude::UNSPENDABLE_INTERNAL_KEY, scripts::prelude::*, types::OperatorIdx,
};

use super::covenant_tx::CovenantTx;
use crate::connectors::prelude::*;

#[derive(Debug, Clone)]
pub struct DisproveData {
    pub post_assert_txid: Txid,

    pub deposit_txid: Txid,

    pub input_stake: Amount,

    pub network: Network,
}

#[derive(Debug, Clone)]
pub struct DisproveTx {
    psbt: Psbt,

    prevouts: Vec<TxOut>,

    witnesses: Vec<TaprootWitness>,
}

impl DisproveTx {
    pub async fn new<Db: PublicDb>(
        data: DisproveData,
        operator_idx: OperatorIdx,
        connector_a30: ConnectorA30<Db>,
        connector_a31: ConnectorA31<Db>,
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

        let connector_a31_script = connector_a31
            .generate_locking_script(data.deposit_txid, operator_idx)
            .await;
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
            connector_a30.generate_spend_info(ConnectorA30Leaf::Disprove);
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

    pub async fn finalize<Db>(
        mut self,
        connector_a30: ConnectorA30<Db>,
        connector_a31: ConnectorA31<Db>,
        reward: TxOut,
        deposit_txid: Txid,
        operator_idx: OperatorIdx,
        disprove_leaf: ConnectorA31Leaf,
    ) -> Transaction
    where
        Db: PublicDb + Clone,
    {
        let original_txid = self.compute_txid();

        connector_a30
            .finalize_input(
                &mut self.psbt.inputs[0],
                operator_idx,
                original_txid,
                ConnectorA30Leaf::Disprove,
            )
            .await;

        connector_a31
            .finalize_input(
                &mut self.psbt.inputs[1],
                disprove_leaf,
                deposit_txid,
                operator_idx,
            )
            .await;

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
}
