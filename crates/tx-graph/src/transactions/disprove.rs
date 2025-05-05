use alpen_bridge_params::prelude::StakeChainParams;
use bitcoin::{
    psbt::{ExtractTxError, PsbtSighashType},
    sighash::Prevouts,
    Amount, Network, OutPoint, Psbt, TapSighashType, Transaction, TxOut, Txid,
};
use strata_bridge_connectors::prelude::*;
use strata_bridge_primitives::scripts::prelude::*;
use strata_primitives::constants::UNSPENDABLE_PUBLIC_KEY;

use super::covenant_tx::CovenantTx;

/// Data needed to construct a [`DisproveTx`].
#[derive(Debug, Clone)]
pub struct DisproveData {
    /// The transaction ID of the post-assert transaction.
    pub post_assert_txid: Txid,

    /// The transaction ID of the deposit transaction.
    pub deposit_txid: Txid,

    /// The stake that remains after deducting all the CPFP dust fees in the preceding
    /// transactions.
    pub input_amount: Amount,

    /// The [`OutPoint`] of the stake transaction that is being spent.
    pub stake_outpoint: OutPoint,

    /// The bitcoin network on which the transaction is to be constructed.
    pub network: Network,
}

pub(crate) const NUM_DISPROVE_INPUTS: usize = 1;

/// The transaction used to disprove an operator's claim and slash their stake.
///
/// Note that this transaction does not contain the second witness as the disprove script is
/// only known at disprove time.
#[derive(Debug, Clone)]
pub struct DisproveTx {
    psbt: Psbt,

    prevouts: [TxOut; 2],

    witnesses: [TaprootWitness; NUM_DISPROVE_INPUTS],
}

impl DisproveTx {
    /// Constructs a new instance of the disprove transaction.
    pub fn new(
        data: DisproveData,
        stake_chain_params: StakeChainParams,
        connector_a3: ConnectorA3,
        connector_stake: ConnectorStake,
    ) -> Self {
        let utxos = [
            data.stake_outpoint,
            OutPoint {
                txid: data.post_assert_txid,
                vout: 0,
            },
        ];

        let tx_ins = create_tx_ins(utxos);

        let (burn_address, _) = create_taproot_addr(
            &data.network,
            SpendPath::KeySpend {
                internal_key: *UNSPENDABLE_PUBLIC_KEY,
            },
        )
        .expect("should be able to create taproot address");
        let burn_script = burn_address.script_pubkey();
        let burn_amount = stake_chain_params.burn_amount;

        let tx_outs = create_tx_outs([(burn_script, burn_amount)]);

        let tx = create_tx(tx_ins, tx_outs);

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("should be able to create psbt");

        let connector_a3_script = connector_a3.generate_locking_script();

        let prevouts = [
            TxOut {
                value: stake_chain_params.stake_amount,
                script_pubkey: connector_stake.generate_address().script_pubkey(),
            },
            TxOut {
                value: data.input_amount,
                script_pubkey: connector_a3_script,
            },
        ];

        let witnesses = [TaprootWitness::Tweaked {
            tweak: connector_stake.generate_merkle_root(),
        }];

        for (input, utxo) in psbt.inputs.iter_mut().zip(prevouts.clone()) {
            input.witness_utxo = Some(utxo);
            input.sighash_type = Some(TapSighashType::Default.into());
        }

        // update the sighash type on the first input.
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
        reward: TxOut,
        stake_path: StakeSpendPath,
        disprove_leaf: ConnectorA3Leaf,
        connector_s: ConnectorStake,
        connector_a3: ConnectorA3,
    ) -> Transaction {
        connector_s.finalize_input(&mut self.psbt.inputs[0], stake_path);
        connector_a3.finalize_input(&mut self.psbt.inputs[1], disprove_leaf);

        let tx = self.psbt.extract_tx();

        match tx {
            Ok(mut tx) => {
                tx.output.push(reward);

                tx
            }
            // this should not error at all but when it does,
            // extract actual error messages instead of using `expect` because these errors
            // include the actual transaction which in the case of `DisproveTx` is too big.
            Err(e) => match e {
                ExtractTxError::AbsurdFeeRate { fee_rate, .. } => {
                    panic!("absured fee rate: {}", fee_rate);
                }
                ExtractTxError::MissingInputValue { .. } => {
                    panic!("missing input value");
                }
                ExtractTxError::SendingTooMuch { psbt } => {
                    let input_amount = psbt
                        .inputs
                        .iter()
                        .map(|i| i.witness_utxo.clone().unwrap().value)
                        .sum::<Amount>();
                    let output_amount = psbt
                        .unsigned_tx
                        .output
                        .iter()
                        .map(|o| o.value)
                        .sum::<Amount>();
                    panic!(
                        "sending too much: input({}) < output({})",
                        input_amount, output_amount
                    );
                }
                unexpected_err => {
                    panic!("unexpected error: {:?}", unexpected_err);
                }
            },
        }
    }
}

impl CovenantTx<NUM_DISPROVE_INPUTS> for DisproveTx {
    fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    fn prevouts(&self) -> Prevouts<'_, TxOut> {
        Prevouts::All(&self.prevouts)
    }

    fn witnesses(&self) -> &[TaprootWitness; 1] {
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
