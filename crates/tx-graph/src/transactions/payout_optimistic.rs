use bitcoin::{
    sighash::Prevouts, taproot, transaction, Amount, Network, OutPoint, Psbt, Sequence,
    TapSighashType, Transaction, TxOut, Txid,
};
use secp256k1::{schnorr, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use strata_bridge_connectors::prelude::{
    ConnectorC0, ConnectorC0Path, ConnectorC1, ConnectorC1Path, ConnectorCpfp, ConnectorNOfN,
    ConnectorP, StakeSpendPath,
};
use strata_bridge_primitives::scripts::prelude::*;

use super::covenant_tx::CovenantTx;

/// Data needed to construct a [`PayoutOptimisticTx`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutOptimisticData {
    /// The transaction ID of the post-assert transaction.
    pub claim_txid: Txid,

    /// The transaction ID of the deposit transaction.
    pub deposit_txid: Txid,

    /// The [`OutPoint`] of the stake transaction.
    pub stake_outpoint: OutPoint,

    /// The amount that remains after paying off the transaction fees in the preceding
    /// transactions.
    pub input_amount: Amount,

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

    prevouts: [TxOut; 5],

    witnesses: [TaprootWitness; 5],
}

impl PayoutOptimisticTx {
    /// Constructs a new instance of the payout optimistic transaction.
    pub fn new(
        data: PayoutOptimisticData,
        connector_c0: ConnectorC0,
        connector_c1: ConnectorC1,
        connector_n_of_n: ConnectorNOfN,
        connector_p: ConnectorP,
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
            OutPoint {
                txid: data.claim_txid,
                vout: 2,
            },
            data.stake_outpoint,
        ];

        let mut tx_ins = create_tx_ins(utxos);

        let c1_input = ConnectorC1Path::PayoutOptimistic(()).get_input_index();
        let c1_input = &mut tx_ins[c1_input as usize];
        c1_input.sequence = Sequence::from_height(connector_c1.payout_optimistic_timelock() as u16);

        let (operator_address, _) = create_taproot_addr(
            &data.network,
            SpendPath::KeySpend {
                internal_key: data.operator_key,
            },
        )
        .expect("should be able to create taproot address");

        let cpfp_script = connector_cpfp.generate_locking_script();
        let cpfp_amount = cpfp_script.minimal_non_dust();

        let n_of_n_addr = connector_n_of_n.create_taproot_address();
        let prevouts = [
            TxOut {
                value: data.deposit_amount,
                script_pubkey: n_of_n_addr.script_pubkey(),
            },
            TxOut {
                value: data.input_amount,
                script_pubkey: connector_c0.generate_locking_script(),
            },
            TxOut {
                value: connector_c1.generate_locking_script().minimal_non_dust(),
                script_pubkey: connector_c1.generate_locking_script(),
            },
            TxOut {
                value: n_of_n_addr.script_pubkey().minimal_non_dust(),
                script_pubkey: n_of_n_addr.script_pubkey(),
            },
            TxOut {
                value: connector_p
                    .generate_address()
                    .script_pubkey()
                    .minimal_non_dust(),
                script_pubkey: connector_p.generate_address().script_pubkey(),
            },
        ];

        let payout_amount = prevouts.iter().map(|out| out.value).sum::<Amount>() - cpfp_amount;
        let tx_outs = create_tx_outs([
            (operator_address.script_pubkey(), payout_amount),
            (cpfp_script, cpfp_amount),
        ]);

        let mut tx = create_tx(tx_ins, tx_outs);
        tx.version = transaction::Version(3);

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("the witness must be empty");

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
            input.sighash_type = Some(TapSighashType::Default.into());
        }

        let (payout_script, control_block) = connector_c1.generate_spend_info();
        let connector_c0_tweak = connector_c0.generate_merkle_root();
        let connector_p_tweak = connector_p.generate_merkle_root();
        let witnesses = [
            TaprootWitness::Key,
            TaprootWitness::Tweaked {
                tweak: connector_c0_tweak,
            },
            TaprootWitness::Script {
                script_buf: payout_script,
                control_block,
            },
            TaprootWitness::Key,
            TaprootWitness::Tweaked {
                tweak: connector_p_tweak,
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
    #[expect(clippy::too_many_arguments)]
    pub fn finalize(
        mut self,
        deposit_signature: schnorr::Signature,
        n_of_n_sig_c0: schnorr::Signature,
        n_of_n_sig_c1: schnorr::Signature,
        n_of_n_sig_c2: schnorr::Signature,
        n_of_n_sig_p: schnorr::Signature,
        connector_c0: ConnectorC0,
        connector_c1: ConnectorC1,
        connector_c2: ConnectorNOfN,
        connector_p: ConnectorP,
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

        let n_of_n_sig_c2 = taproot::Signature {
            signature: n_of_n_sig_c2,
            sighash_type: TapSighashType::Default,
        };
        connector_c2.finalize_input(&mut self.psbt.inputs[3], n_of_n_sig_c2);

        let p_witness = StakeSpendPath::PayoutOptimistic(n_of_n_sig_p);
        let p_input_index = p_witness.get_input_index() as usize;
        connector_p.finalize(&mut self.psbt.inputs[p_input_index], p_witness);

        self.psbt
            .extract_tx()
            .expect("should be able to extract tx")
    }
}

impl CovenantTx<5> for PayoutOptimisticTx {
    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    fn prevouts(&self) -> Prevouts<'_, TxOut> {
        Prevouts::All(&self.prevouts)
    }

    fn witnesses(&self) -> &[TaprootWitness; 5] {
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
