//! Constructs the claim transaction.

use bitcoin::{transaction, Amount, OutPoint, Psbt, TapSighashType, Transaction, TxOut, Txid};
use bitvm::signatures::{Wots, Wots32 as wots256};
use strata_bridge_connectors::prelude::*;
use strata_bridge_primitives::{constants::FUNDING_AMOUNT, scripts::prelude::*};

use super::errors::{TxError, TxResult};

/// Data needed to construct a [`ClaimTx`].
#[derive(Debug, Clone)]
pub struct ClaimData {
    /// The [`OutPoint`] of the stake transaction that is being spent.
    pub stake_outpoint: OutPoint,

    /// The deposit transaction id.
    pub deposit_txid: Txid,
}

/// The claim transaction.
#[derive(Debug, Clone)]
pub struct ClaimTx {
    /// The psbt that contains the inputs and outputs for the transaction.
    psbt: Psbt,

    /// The amount of the output.
    output_amount: Amount,

    /// The connector for the kickoff and claim transactions.
    connector_k: ConnectorK,
}

/// The vout used in the challenge/pre-assert transactions.
pub const CHALLENGE_VOUT: u32 = 1;

/// The vout used in the payout transaction to reimburse the operator.
pub const PAYOUT_VOUT: u32 = 2;

/// The vout that is spent by the slash stake transaction.
pub const SLASH_STAKE_VOUT: u32 = 2;

impl ClaimTx {
    /// Creates a new claim transaction.
    pub fn new(
        data: ClaimData,
        connector_k: ConnectorK,
        connector_c0: ConnectorC0,
        connector_c1: ConnectorC1,
        connector_n_of_n: ConnectorNOfN,
        connector_cpfp: ConnectorCpfp,
    ) -> Self {
        let input_amount = FUNDING_AMOUNT;

        let tx_ins = create_tx_ins([data.stake_outpoint]);

        let c1_out = connector_c1.generate_locking_script();
        let c1_amt = c1_out.minimal_non_dust();

        let c2_out = connector_n_of_n.create_taproot_address().script_pubkey();
        let c2_amt = c2_out.minimal_non_dust();

        let cpfp_script = connector_cpfp.generate_locking_script();
        let cpfp_amt = cpfp_script.minimal_non_dust();

        let c0_out = connector_c0.generate_locking_script();
        let c0_amt = input_amount - c1_amt - c2_amt - cpfp_amt;

        let scripts_and_amounts = [
            (c0_out, c0_amt),
            (c1_out, c1_amt),
            (c2_out, c2_amt),
            (cpfp_script, cpfp_amt),
        ];

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let mut tx = create_tx(tx_ins, tx_outs);
        tx.version = transaction::Version(3);

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("tx should have an empty witness");

        let prevout = TxOut {
            value: input_amount,
            script_pubkey: connector_k.create_taproot_address().script_pubkey(),
        };

        psbt.inputs[0].witness_utxo = Some(prevout.clone());
        psbt.inputs[0].sighash_type = Some(TapSighashType::Default.into());

        Self {
            psbt,
            output_amount: c0_amt,
            connector_k,
        }
    }

    /// The underlying PSBT.
    pub const fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    /// A mutable reference to the underlying PSBT.
    pub const fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    /// Computes the txid of the transaction.
    pub fn compute_txid(&self) -> Txid {
        self.psbt.unsigned_tx.compute_txid()
    }

    /// The input amount of the transaction.
    pub fn input_amount(&self) -> Amount {
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

    /// The output amount of the transaction.
    pub const fn output_amount(&self) -> Amount {
        self.output_amount
    }

    /// The vout for the CPFP output.
    pub const fn cpfp_vout(&self) -> u32 {
        self.psbt.outputs.len() as u32 - 1
    }

    /// The vout for the slash stake output.
    pub const fn slash_stake_vout(&self) -> u32 {
        SLASH_STAKE_VOUT
    }

    /// Finalizes the transaction with the signature.
    pub fn finalize(mut self, signature: <wots256 as Wots>::Signature) -> Transaction {
        self.connector_k
            .finalize_input(&mut self.psbt.inputs[0], signature);

        self.psbt
            .extract_tx()
            .expect("should be able to extract signed tx")
    }

    /// Parses the witness from the transaction and returns the WOTS256 signature.
    ///
    /// # Errors
    ///
    /// If the structure of the transaction witness does not match that of the claim transaction.
    pub fn parse_witness(tx: &Transaction) -> TxResult<<wots256 as Wots>::Signature> {
        let witness = &tx
            .input
            .first()
            .expect("must have at least one input")
            .witness;

        if witness.is_empty() {
            return Err(TxError::Witness(
                "witness is empty, tx is not signed".to_string(),
            ));
        }

        let witness_txid = witness.to_vec();

        let wots256_signature: Result<<wots256 as Wots>::Signature, TxError> =
            std::array::try_from_fn(|i| {
                let (i, j) = (2 * i, 2 * i + 1);
                let preimage: [u8; 20] = witness_txid[i].clone().try_into().map_err(|_e| {
                    TxError::Witness(format!("txid size invalid: {}", witness_txid[i].len()))
                })?;
                let digit = if witness_txid[j].is_empty() {
                    0
                } else {
                    witness_txid[j][0]
                };

                let mut sig = Vec::with_capacity(wots256::TOTAL_DIGIT_LEN as usize);
                sig.extend_from_slice(&preimage);
                sig.push(digit);

                sig.try_into()
                    .map_err(|_| TxError::Witness("wots256 signature size invalid".to_string()))
            });

        let wots256_signature = wots256_signature?;

        Ok(wots256_signature)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use bitcoin::{hashes::Hash, Network, Witness};
    use bitvm::treepp::*;
    use strata_bridge_primitives::{
        build_context::{BuildContext, TxBuildContext},
        wots::{self, Wots256Sig},
    };
    use strata_bridge_test_utils::prelude::{generate_keypair, generate_txid};

    use super::*;

    #[test]
    fn test_parse_witness() {
        let keypair = generate_keypair();
        let pubkey = keypair.public_key().x_only_public_key().0;
        let network = Network::Regtest;
        let msk = "test-parse-witness";
        let deposit_txid = generate_txid();

        let pubkey_table = BTreeMap::from([(0, keypair.public_key().into())]);
        let build_context = TxBuildContext::new(network, pubkey_table.into(), 0);

        let wots_public_key = wots::Wots256PublicKey::new(msk, deposit_txid);
        let pre_assert_timelock = 11;
        let payout_optimistic_timelock = 10;
        let claim_tx = ClaimTx::new(
            ClaimData {
                stake_outpoint: OutPoint {
                    txid: generate_txid(),
                    vout: 0,
                },
                deposit_txid,
            },
            ConnectorK::new(network, wots_public_key.clone()),
            ConnectorC0::new(pubkey, network, pre_assert_timelock),
            ConnectorC1::new(pubkey, network, payout_optimistic_timelock),
            ConnectorNOfN::new(build_context.aggregated_pubkey(), network),
            ConnectorCpfp::new(pubkey, network),
        );

        let withdrawal_fulfillment_txid = generate_txid();

        let signature = Wots256Sig::new(
            msk,
            deposit_txid,
            withdrawal_fulfillment_txid.as_byte_array(),
        );
        let mut signed_claim_tx = claim_tx.finalize(*signature);

        let parsed_wots256 =
            ClaimTx::parse_witness(&signed_claim_tx).expect("must be able to parse claim witness");

        let full_script = script! {
            for sig_with_digit in parsed_wots256 {
                { sig_with_digit[..20].to_vec() }
                { sig_with_digit[20] }
            }
            { wots256::checksig_verify(&wots_public_key.0) }
            for _ in 0..256/4 { OP_DROP } // drop all nibbles

            OP_TRUE
        };

        assert!(
            execute_script(full_script).success,
            "must be able to execute valid script"
        );

        signed_claim_tx.input[0].witness =
            Witness::from_slice(&[[0u8; 32]; 4 * wots256::TOTAL_DIGIT_LEN as usize]);
        assert!(
            ClaimTx::parse_witness(&signed_claim_tx)
                .is_err_and(|e| e.to_string().contains("size invalid")),
            "must not be able to parse"
        );
    }
}
