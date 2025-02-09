use bitcoin::{ScriptBuf, Transaction, Txid};
use strata_l1tx::envelope::parser::parse_envelope_payloads;
use strata_primitives::{
    block_credential::CredRule, bridge::OperatorIdx, l1::BitcoinAmount, params::RollupParams,
};
use strata_proofimpl_btc_blockspace::tx::compute_txid;
use strata_state::batch::{BatchCheckpoint, SignedBatchCheckpoint};

use crate::error::{BridgeProofError, BridgeRelatedTx};

pub(crate) fn extract_checkpoint(
    tx: &Transaction,
    rollup_params: &RollupParams,
) -> Result<BatchCheckpoint, BridgeProofError> {
    for inp in &tx.input {
        if let Some(scr) = inp.witness.tapscript() {
            if let Ok(payload) = parse_envelope_payloads(&scr.into(), rollup_params) {
                if let Ok(checkpoint) =
                    // TODO: fix this
                    borsh::from_slice::<SignedBatchCheckpoint>(payload[0].data())
                {
                    if let CredRule::SchnorrKey(seq_pubkey) = &rollup_params.cred_rule {
                        assert!(
                            checkpoint.verify_sig(seq_pubkey),
                            "invalid signature for checkpoint"
                        );
                    }
                    return Ok(checkpoint.into());
                }
            }
        }
    }

    Err(BridgeProofError::TxInfoExtractionError(
        BridgeRelatedTx::StrataCheckpoint,
    ))
}

// TODO: make this standard
// FIX: slicing without properly checking the info causes panic
// TODO: maybe turn the output into a struct
pub(crate) fn extract_withdrawal_info(
    tx: &Transaction,
) -> Result<(OperatorIdx, ScriptBuf, BitcoinAmount), BridgeProofError> {
    if tx.output.len() < 2 {
        return Err(BridgeProofError::TxInfoExtractionError(
            BridgeRelatedTx::WithdrawalFulfillment,
        ));
    }

    let operator_idx_output = &tx.output[0];
    let withdrawal_fulfillment_output = &tx.output[1];

    let operator_id = u32::from_be_bytes(
        operator_idx_output.script_pubkey.as_bytes()[2..6]
            .try_into()
            .map_err(|_| {
                BridgeProofError::TxInfoExtractionError(BridgeRelatedTx::WithdrawalFulfillment)
            })?,
    );
    let withdrawal_amount = BitcoinAmount::from_sat(withdrawal_fulfillment_output.value.to_sat());
    let withdrawal_address = withdrawal_fulfillment_output.script_pubkey.clone();
    Ok((operator_id, withdrawal_address, withdrawal_amount))
}

/// Returns:
///
/// 2. committed witdrawal fulfillment tx id
pub(crate) fn extract_claim_info(tx: &Transaction) -> Result<Txid, BridgeProofError> {
    // TODO: FIXME
    Ok(compute_txid(tx).into())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use bitcoin::Block;
    use strata_primitives::params::RollupParams;

    use super::extract_checkpoint;
    use crate::tx_info::extract_withdrawal_info;

    fn get_data() -> (Vec<Block>, RollupParams) {
        let blocks_bytes = std::fs::read("../../../test-data/blocks.bin").unwrap();
        let blocks: Vec<Block> = bincode::deserialize(&blocks_bytes).unwrap();

        let json = fs::read_to_string("../../../test-data/rollup_params.json")
            .expect("rollup params file not found");
        let rollup_params: RollupParams = serde_json::from_str(&json).unwrap();
        rollup_params.check_well_formed().unwrap();

        (blocks, rollup_params)
    }

    #[test]
    fn test_extract_checkpoint() {
        let (blocks, rollup_params) = get_data();
        let starting_height = blocks.first().unwrap().bip34_block_height().unwrap();
        let checkpoint_inscribed_height = 968;
        let checkpoint_inscribed_tx_idx = 2;

        let block = blocks[(checkpoint_inscribed_height - starting_height) as usize].clone();
        let tx = block.txdata[checkpoint_inscribed_tx_idx].clone();

        let res = extract_checkpoint(&tx, &rollup_params);
        assert!(res.is_ok());
        dbg!(res.unwrap());
    }

    #[test]
    fn test_extract_withdrawal_info() {
        let (blocks, _) = get_data();
        let starting_height = blocks.first().unwrap().bip34_block_height().unwrap();
        let withdrawal_fulfillment_height = 988;
        let withdrawal_fulfillment_tx_idx = 1;

        let block = blocks[(withdrawal_fulfillment_height - starting_height) as usize].clone();
        let tx = block.txdata[withdrawal_fulfillment_tx_idx].clone();
        dbg!(&tx);

        let res = extract_withdrawal_info(&tx);
        assert!(res.is_ok());
        dbg!(res.unwrap());
    }
}
