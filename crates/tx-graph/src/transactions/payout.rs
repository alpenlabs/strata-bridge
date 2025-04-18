use bitcoin::{
    sighash::Prevouts, taproot, transaction, Amount, Network, OutPoint, Psbt, Sequence,
    TapSighashType, Transaction, TxOut, Txid,
};
use secp256k1::{schnorr, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use strata_bridge_connectors::prelude::{
    ConnectorA3, ConnectorA3Leaf, ConnectorCpfp, ConnectorNOfN, ConnectorP, StakeSpendPath,
};
use strata_bridge_primitives::scripts::prelude::*;

use super::covenant_tx::CovenantTx;

/// Data needed to construct a [`PayoutTx`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayoutData {
    /// The transaction ID of the post-assert transaction.
    pub post_assert_txid: Txid,

    /// The transaction ID of the deposit transaction.
    pub deposit_txid: Txid,

    /// The [`OutPoint`] of the Claim transaction.
    pub claim_outpoint: OutPoint,

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
pub struct PayoutTx {
    psbt: Psbt,

    prevouts: [TxOut; 4],

    witnesses: [TaprootWitness; 4],
}

impl PayoutTx {
    /// Constructs a new instance of the payout transaction.
    pub fn new(
        data: PayoutData,
        connector_a3: ConnectorA3,
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
                txid: data.post_assert_txid,
                vout: 0,
            },
            data.claim_outpoint,
            data.stake_outpoint,
        ];

        let mut tx_ins = create_tx_ins(utxos);

        let stake_input = &mut tx_ins[1];
        stake_input.sequence = Sequence::from_height(connector_a3.payout_timelock() as u16);

        assert!(
            stake_input.sequence.is_relative_lock_time(),
            "must set relative timelock on the second input of payout tx"
        );

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
                script_pubkey: connector_a3.generate_locking_script(data.deposit_txid),
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

        let (connector_a3_script, connector_a3_control_block) =
            connector_a3.generate_spend_info(ConnectorA3Leaf::Payout(None), data.deposit_txid);
        let witnesses = [
            TaprootWitness::Key,
            TaprootWitness::Script {
                script_buf: connector_a3_script,
                control_block: connector_a3_control_block,
            },
            TaprootWitness::Key,
            TaprootWitness::Tweaked {
                tweak: connector_p.generate_merkle_root(),
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

    /// Finalizes the payout transaction.
    ///
    /// Note that the `deposit_signature` is also an n-of-n signature.
    #[expect(clippy::too_many_arguments)]
    pub fn finalize(
        mut self,
        deposit_signature: schnorr::Signature,
        n_of_n_sig_a3: schnorr::Signature,
        n_of_n_sig_c2: schnorr::Signature,
        n_of_n_sig_p: schnorr::Signature,
        connector_a3: ConnectorA3,
        connector_c2: ConnectorNOfN,
        connector_p: ConnectorP,
    ) -> Transaction {
        finalize_input(&mut self.psbt.inputs[0], [deposit_signature.serialize()]);

        connector_a3.finalize_input(
            &mut self.psbt.inputs[1],
            ConnectorA3Leaf::Payout(Some(n_of_n_sig_a3)),
        );

        let n_of_n_sig_c2 = taproot::Signature {
            signature: n_of_n_sig_c2,
            sighash_type: TapSighashType::Default,
        };
        connector_c2.finalize_input(&mut self.psbt.inputs[2], n_of_n_sig_c2);

        let spend_path = StakeSpendPath::Payout(n_of_n_sig_p);
        connector_p.finalize(&mut self.psbt.inputs[3], spend_path);

        self.psbt
            .extract_tx()
            .expect("should be able to extract tx")
    }
}

impl CovenantTx<4> for PayoutTx {
    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    fn prevouts(&self) -> Prevouts<'_, TxOut> {
        Prevouts::All(&self.prevouts)
    }

    fn witnesses(&self) -> &[TaprootWitness; 4] {
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
