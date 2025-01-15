use bitcoin::{Amount, OutPoint, Psbt, Transaction, TxOut, Txid};
use bitvm::signatures::wots::{wots256, wots32};
use strata_bridge_primitives::{
    params::prelude::{MIN_RELAY_FEE, OPERATOR_STAKE},
    scripts::prelude::*,
};

use super::errors::{TxError, TxResult};
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
}

impl ClaimTx {
    pub fn new(
        data: ClaimData,
        connector_k: ConnectorK,
        connector_c0: ConnectorC0,
        connector_c1: ConnectorC1,
    ) -> Self {
        let tx_ins = create_tx_ins([OutPoint {
            txid: data.kickoff_txid,
            vout: 0,
        }]);

        let c1_out = connector_c1.generate_locking_script();
        let c1_amt = c1_out.minimal_non_dust();

        let c0_amt = OPERATOR_STAKE - c1_amt - MIN_RELAY_FEE; // use stake for intermediate fees

        let scripts_and_amounts = [
            (connector_c0.generate_locking_script(), c0_amt),
            (connector_c1.generate_locking_script(), c1_amt),
        ];

        let tx_outs = create_tx_outs(scripts_and_amounts);

        let tx = create_tx(tx_ins, tx_outs);

        let mut psbt = Psbt::from_unsigned_tx(tx).expect("tx should have an empty witness");

        psbt.inputs[0].witness_utxo = Some(TxOut {
            value: OPERATOR_STAKE,
            script_pubkey: connector_k.create_taproot_address().script_pubkey(),
        });

        Self {
            psbt,
            remaining_stake: c0_amt,
        }
    }

    pub fn psbt(&self) -> &Psbt {
        &self.psbt
    }

    pub fn psbt_mut(&mut self) -> &mut Psbt {
        &mut self.psbt
    }

    pub fn remaining_stake(&self) -> Amount {
        self.remaining_stake
    }

    pub fn compute_txid(&self) -> Txid {
        self.psbt.unsigned_tx.compute_txid()
    }

    pub fn finalize(
        mut self,
        deposit_txid: Txid,
        connector_k: &ConnectorK,
        msk: &str,
        bridge_out_txid: Txid,
        superblock_period_start_ts: u32,
    ) -> Transaction {
        let (script, control_block) = connector_k.generate_spend_info();

        connector_k.create_tx_input(
            &mut self.psbt.inputs[0],
            msk,
            bridge_out_txid,
            superblock_period_start_ts,
            deposit_txid,
            script,
            control_block,
        );

        self.psbt
            .extract_tx()
            .expect("should be able to extract signed tx")
    }

    pub fn parse_witness(
        tx: &Transaction,
    ) -> TxResult<Option<(wots32::Signature, wots256::Signature)>> {
        let witness = &tx
            .input
            .first()
            .expect("must have at least one input")
            .witness;

        if witness.is_empty() {
            return Ok(None);
        }

        let witness = witness.to_vec();

        let (witness_txid, witness_ts) =
            witness
                .split_at_checked(2 * wots256::N_DIGITS as usize)
                .ok_or(TxError::Witness("witness too short".to_string()))?;

        let wots32_signature: Result<wots32::Signature, TxError> = std::array::try_from_fn(|i| {
            let (i, j) = (2 * i, 2 * i + 1);
            let preimage = witness_ts[i].clone().try_into().map_err(|_e| {
                TxError::Witness(format!("T_s size invalid: {}", witness_ts[i].len()))
            })?;
            let digit = if witness_ts[j].is_empty() {
                0
            } else {
                witness_ts[j][0]
            };

            Ok((preimage, digit))
        });
        let wots32_signature = wots32_signature?;

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

        Ok(Some((wots32_signature, wots256_signature)))
    }
}

#[cfg(test)]
mod tests {
    use std::time::{self, UNIX_EPOCH};

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
        );

        let connector_k = ConnectorK::new(pubkey, network, wots_public_keys);
        let bridge_out_txid = generate_txid();
        let superblock_period_start_ts = time::SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let mut signed_claim_tx = claim_tx.finalize(
            deposit_txid,
            &connector_k,
            msk,
            bridge_out_txid,
            superblock_period_start_ts,
        );

        let (parsed_wots32, parsed_wots256) = ClaimTx::parse_witness(&signed_claim_tx)
            .expect("must be able to parse")
            .expect("must have witness");

        let full_script = script! {
            for (sig, digit) in parsed_wots32 {
                { sig.to_vec() }
                { digit }
            }

            { wots32::checksig_verify(wots_public_keys.superblock_period_start_ts.0, true) }

            for (sig, digit) in parsed_wots256 {
                { sig.to_vec() }
                { digit }
            }
            { wots256::checksig_verify(wots_public_keys.bridge_out_txid.0, true) }

            OP_TRUE
        };

        assert!(
            execute_script(full_script).success,
            "must be able to execute valid script"
        );

        signed_claim_tx.input[0].witness = Witness::from_slice(&[[0u8; 32]; 1]);
        assert!(
            ClaimTx::parse_witness(&signed_claim_tx)
                .is_err_and(|e| { e.to_string().contains("too short") }),
            "must not be able to parse"
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
