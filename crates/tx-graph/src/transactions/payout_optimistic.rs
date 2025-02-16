use bitcoin::{
    sighash::Prevouts, taproot, transaction, Amount, Network, OutPoint, Psbt, Sequence,
    Transaction, TxOut, Txid,
};
use secp256k1::{schnorr, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use strata_bridge_primitives::{params::prelude::PAYOUT_OPTIMISTIC_TIMELOCK, scripts::prelude::*};

use super::covenant_tx::CovenantTx;
use crate::connectors::prelude::{
    ConnectorC0, ConnectorC0Path, ConnectorC1, ConnectorC1Path, ConnectorCpfp, ConnectorS,
};

/// Data needed to construct a [`PayoutOptimisticTx`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutOptimisticData {
    /// The transaction ID of the post-assert transaction.
    pub claim_txid: Txid,

    /// The transaction ID of the deposit transaction.
    pub deposit_txid: Txid,

    /// The stake that remains after paying off the transaction fees in the preceding transactions.
    pub input_stake: Amount,

    /// The amount of the deposit.
    ///
    /// This is the amount held in a particular UTXO in the Bridge Address used to reimburse the
    /// operator.
    pub deposit_amount: Amount,

    /// The operator's public key corresponding to the address that the operator wants to be paid
    /// to.
    pub operator_key: XOnlyPublicKey,

    /// The bitcoin network on which the transaction is to be constructed.
    pub network: Network,
}

/// A transaction that reimburses a *functional* operator.
#[derive(Debug, Clone)]
pub struct PayoutOptimisticTx {
    psbt: Psbt,

    prevouts: Vec<TxOut>,

    witnesses: Vec<TaprootWitness>,
}

impl PayoutOptimisticTx {
    /// Constructs a new instance of the payout optimistic transaction.
    pub fn new(
        data: PayoutOptimisticData,
        connector_c0: ConnectorC0,
        connector_c1: ConnectorC1,
        connector_b: ConnectorS,
        connector_cpfp: ConnectorCpfp,
    ) -> Self {
        let utxos = [
            OutPoint {
                txid: data.deposit_txid,
                vout: 0,
            },
            OutPoint {
                txid: data.claim_txid,
                vout: 0,
            },
            OutPoint {
                txid: data.claim_txid,
                vout: 1,
            },
        ];

        let mut tx_ins = create_tx_ins(utxos);

        let c1_input = ConnectorC1Path::PayoutOptimistic(()).get_input_index();
        let c1_input = &mut tx_ins[c1_input as usize];
        c1_input.sequence = Sequence::from_height(PAYOUT_OPTIMISTIC_TIMELOCK as u16);

        let (operator_address, _) = create_taproot_addr(
            &data.network,
            SpendPath::KeySpend {
                internal_key: data.operator_key,
            },
        )
        .expect("should be able to create taproot address");

        let cpfp_script = connector_cpfp.generate_locking_script();
        let cpfp_amount = cpfp_script.minimal_non_dust();

        let payout_amount = data.input_stake + data.deposit_amount - cpfp_amount;

        let tx_outs = create_tx_outs([
            (operator_address.script_pubkey(), payout_amount),
            (cpfp_script, cpfp_amount),
        ]);

        let mut tx = create_tx(tx_ins, tx_outs);
        tx.version = transaction::Version(3);

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("the witness must be empty");

        let prevouts = vec![
            TxOut {
                value: data.deposit_amount,
                script_pubkey: connector_b.create_taproot_address().script_pubkey(),
            },
            TxOut {
                value: data.input_stake,
                script_pubkey: connector_c0.generate_locking_script(),
            },
            TxOut {
                value: connector_c1.generate_locking_script().minimal_non_dust(),
                script_pubkey: connector_c1.generate_locking_script(),
            },
        ];

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
        }

        let (payout_script, control_block) = connector_c1.generate_spend_info();
        let connector_c0_tweak = connector_c0.generate_merkle_root();
        let witnesses = vec![
            TaprootWitness::Key,
            TaprootWitness::Tweaked {
                tweak: connector_c0_tweak,
            },
            TaprootWitness::Script {
                script_buf: payout_script,
                control_block,
            },
        ];

        Self {
            psbt,

            prevouts,
            witnesses,
        }
    }

    /// Gets the output index for CPFP.
    pub fn cpfp_vout(&self) -> u32 {
        self.psbt.outputs.len() as u32 - 1
    }

    /// Finalizes the payout optimistic transaction.
    ///
    /// Note that the `deposit_signature` is also an n-of-n signature.
    pub fn finalize(
        mut self,
        connector_c0: ConnectorC0,
        connector_c1: ConnectorC1,
        n_of_n_sig_c0: schnorr::Signature,
        n_of_n_sig_c1: schnorr::Signature,
        deposit_signature: schnorr::Signature,
    ) -> Transaction {
        finalize_input(&mut self.psbt.inputs[0], [deposit_signature.serialize()]);

        let c0_path = ConnectorC0Path::PayoutOptimistic(()).add_witness_data(n_of_n_sig_c0);
        let c0_input_index = c0_path.get_input_index() as usize;
        connector_c0.finalize_input(&mut self.psbt.inputs[c0_input_index], c0_path);

        let c1_path = ConnectorC1Path::PayoutOptimistic(());
        let c1_path = c1_path.add_witness_data(taproot::Signature {
            signature: n_of_n_sig_c1,
            sighash_type: c1_path.get_sighash_type(),
        });
        let c1_input_index = c1_path.get_input_index() as usize;
        connector_c1.finalize_input(&mut self.psbt.inputs[c1_input_index], c1_path);

        self.psbt
            .extract_tx()
            .expect("should be able to extract tx")
    }
}

impl CovenantTx for PayoutOptimisticTx {
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
                    .expect("must have witness utxo")
                    .value
            })
            .sum()
    }
}
