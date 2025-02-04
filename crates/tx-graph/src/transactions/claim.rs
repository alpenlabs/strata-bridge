use bitcoin::{sighash::Prevouts, transaction, Amount, OutPoint, Psbt, Transaction, TxOut, Txid};
use bitvm::signatures::wots::wots256;
use strata_bridge_primitives::{params::prelude::OPERATOR_STAKE, scripts::prelude::*};

use super::{
    errors::{TxError, TxResult},
    prelude::CovenantTx,
};
use crate::connectors::prelude::*;

/// Data needed to construct a [`ClaimTx`].
#[derive(Debug, Clone)]
pub struct ClaimData {
    pub kickoff_txid: Txid,

    pub deposit_txid: Txid,
}

#[derive(Debug, Clone)]
pub struct ClaimTx {
    psbt: Psbt,

    remaining_stake: Amount,

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
        let tx_ins = create_tx_ins([OutPoint {
            txid: data.kickoff_txid,
            vout: 0,
        }]);

        let c1_out = connector_c1.generate_locking_script();
        let c1_amt = c1_out.minimal_non_dust();

        let cpfp_script = connector_cpfp.generate_locking_script();
        let cpfp_amt = cpfp_script.minimal_non_dust();

        let c0_amt = OPERATOR_STAKE - c1_amt - cpfp_amt;

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
            value: OPERATOR_STAKE,
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
            remaining_stake: c0_amt,
            prevouts: vec![prevout],
            witnesses,
        }
    }

    pub fn remaining_stake(&self) -> Amount {
        self.remaining_stake
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

        let wots_public_keys: wots::PublicKeys = wots::PublicKeys::new(msk, deposit_txid);
        let claim_tx = ClaimTx::new(
            ClaimData {
                kickoff_txid: generate_txid(),
                deposit_txid,
            },
            ConnectorK::new(pubkey, network, wots_public_keys),
            ConnectorC0::new(pubkey, network),
            ConnectorC1::new(pubkey, network),
            ConnectorCpfp::new(pubkey, network),
        );

        let connector_k = ConnectorK::new(pubkey, network, wots_public_keys);
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
            { wots256::checksig_verify(wots_public_keys.withdrawal_fulfillment_pk.0, true) }

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
