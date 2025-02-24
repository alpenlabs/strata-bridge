use bitcoin::{sighash::Prevouts, transaction, Amount, OutPoint, Psbt, Transaction, TxOut, Txid};
use bitvm::signatures::wots_api::wots256;
use strata_bridge_connectors::prelude::*;
use strata_bridge_primitives::scripts::prelude::*;

use super::{
    errors::{TxError, TxResult},
    prelude::CovenantTx,
};

/// Data needed to construct a [`ClaimTx`].
#[derive(Debug, Clone)]
pub struct ClaimData {
    /// The [`OutPoint`] of the stake transaction that is being spent.
    pub stake_outpoint: OutPoint,

    /// The deposit transaction id.
    pub deposit_txid: Txid,

    /// The amount in the input (from the stake transaction).
    pub input_amount: Amount,
}

#[derive(Debug, Clone)]
pub struct ClaimTx {
    psbt: Psbt,

    output_amount: Amount,

    prevouts: Vec<TxOut>,
    witnesses: Vec<TaprootWitness>,
}

impl ClaimTx {
    pub fn new(
        data: ClaimData,
        connector_k: ConnectorK,
        connector_c0: ConnectorC0,
        connector_c1: ConnectorC1,
        connector_cpfp: ConnectorCpfp,
    ) -> Self {
        let tx_ins = create_tx_ins([data.stake_outpoint]);

        let c1_out = connector_c1.generate_locking_script();
        let c1_amt = c1_out.minimal_non_dust();

        let cpfp_script = connector_cpfp.generate_locking_script();
        let cpfp_amt = cpfp_script.minimal_non_dust();

        let c0_amt = data.input_amount - c1_amt - cpfp_amt;

        let scripts_and_amounts = [
            (connector_c0.generate_locking_script(), c0_amt),
            (connector_c1.generate_locking_script(), c1_amt),
            (cpfp_script, cpfp_amt),
        ];

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let mut tx = create_tx(tx_ins, tx_outs);
        tx.version = transaction::Version(3);

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("tx should have an empty witness");

        let prevout = TxOut {
            value: data.input_amount,
            script_pubkey: connector_k.create_taproot_address().script_pubkey(),
        };

        psbt.inputs[0].witness_utxo = Some(prevout.clone());

        let (input_script, control_block) = connector_k.generate_spend_info();
        let witnesses = vec![TaprootWitness::Script {
            script_buf: input_script,
            control_block,
        }];

        Self {
            psbt,
            output_amount: c0_amt,
            prevouts: vec![prevout],
            witnesses,
        }
    }

    pub fn output_amount(&self) -> Amount {
        self.output_amount
    }

    pub fn cpfp_vout(&self) -> u32 {
        self.psbt.outputs.len() as u32 - 1
    }

    pub fn finalize(
        mut self,
        deposit_txid: Txid,
        connector_k: &ConnectorK,
        msk: &str,
        withdrawal_fulfillment_txid: Txid,
    ) -> Transaction {
        let (script, control_block) = connector_k.generate_spend_info();

        connector_k.create_tx_input(
            &mut self.psbt.inputs[0],
            msk,
            withdrawal_fulfillment_txid,
            deposit_txid,
            script,
            control_block,
        );

        self.psbt
            .extract_tx()
            .expect("should be able to extract signed tx")
    }

    pub fn parse_witness(tx: &Transaction) -> TxResult<Option<wots256::Signature>> {
        let witness = &tx
            .input
            .first()
            .expect("must have at least one input")
            .witness;

        if witness.is_empty() {
            return Ok(None);
        }

        let witness_txid = witness.to_vec();

        let wots256_signature: Result<wots256::Signature, TxError> = std::array::try_from_fn(|i| {
            let (i, j) = (2 * i, 2 * i + 1);
            let preimage = witness_txid[i].clone().try_into().map_err(|_e| {
                TxError::Witness(format!("txid size invalid: {}", witness_txid[i].len()))
            })?;
            let digit = if witness_txid[j].is_empty() {
                0
            } else {
                witness_txid[j][0]
            };

            Ok((preimage, digit))
        });

        let wots256_signature = wots256_signature?;

        Ok(Some(wots256_signature))
    }
}

impl CovenantTx for ClaimTx {
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

    fn input_amount(&self) -> Amount {
        self.psbt
            .inputs
            .iter()
            .map(|out| {
                out.witness_utxo
                    .as_ref()
                    .expect("psbt must have witness")
                    .value
            })
            .sum()
    }

    fn compute_txid(&self) -> Txid {
        self.psbt.unsigned_tx.compute_txid()
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::{Network, Witness};
    use bitvm::treepp::*;
    use secp256k1::rand::{rngs::OsRng, Rng};
    use strata_bridge_primitives::wots;
    use strata_bridge_test_utils::prelude::{generate_keypair, generate_txid};

    use super::*;

    #[test]
    fn test_parse_witness() {
        let keypair = generate_keypair();
        let pubkey = keypair.public_key().x_only_public_key().0;
        let network = Network::Regtest;
        let msk = "test-parse-witness";
        let deposit_txid = generate_txid();

        let wots_sk = get_deposit_master_secret_key(msk, deposit_txid);
        let wots_public_key = wots::Wots256PublicKey::new(&wots_sk);
        let claim_tx = ClaimTx::new(
            ClaimData {
                stake_outpoint: OutPoint {
                    txid: generate_txid(),
                    vout: 0,
                },
                deposit_txid,
                input_amount: Amount::from_sat(OsRng.gen_range(1..100_000)),
            },
            ConnectorK::new(pubkey, network, wots_public_key),
            ConnectorC0::new(pubkey, network),
            ConnectorC1::new(pubkey, network),
            ConnectorCpfp::new(pubkey, network),
        );

        let connector_k = ConnectorK::new(pubkey, network, wots_public_key);
        let withdrawal_fulfillment_txid = generate_txid();

        let mut signed_claim_tx =
            claim_tx.finalize(deposit_txid, &connector_k, msk, withdrawal_fulfillment_txid);

        let parsed_wots256 = ClaimTx::parse_witness(&signed_claim_tx)
            .expect("must be able to parse")
            .expect("must have witness");

        let full_script = script! {
            for (sig, digit) in parsed_wots256 {
                { sig.to_vec() }
                { digit }
            }
            { wots256::checksig_verify(wots_public_key.0) }
            for _ in 0..256/4 { OP_DROP } // drop all nibbles

            OP_TRUE
        };

        assert!(
            execute_script(full_script).success,
            "must be able to execute valid script"
        );

        signed_claim_tx.input[0].witness =
            Witness::from_slice(&[[0u8; 32]; 4 * wots256::N_DIGITS as usize]);
        assert!(
            ClaimTx::parse_witness(&signed_claim_tx)
                .is_err_and(|e| e.to_string().contains("size invalid")),
            "must not be able to parse"
        );

        signed_claim_tx.input[0].witness = Witness::new();
        assert!(
            ClaimTx::parse_witness(&signed_claim_tx).is_ok_and(|v| v.is_none()),
            "must not have witness"
        );
    }
}
