use bitcoin::{ScriptBuf, Transaction};
use strata_l1tx::envelope::parser::parse_envelope_payloads;
use strata_primitives::{
    block_credential::CredRule, bridge::OperatorIdx, l1::BitcoinAmount, params::RollupParams,
};
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

#[cfg(test)]
mod tests {
    use prover_test_utils::{
        extract_test_headers, get_strata_checkpoint_tx, load_test_rollup_params,
    };
    use strata_proofimpl_btc_blockspace::tx::compute_txid;

    use super::*;
    use crate::tx_info::extract_withdrawal_info;

    #[test]
    fn test_extract_checkpoint() {
        let headers = extract_test_headers();
        let (checkpoint_inscribed_tx_bundle, idx) = get_strata_checkpoint_tx();
        assert!(checkpoint_inscribed_tx_bundle.verify(headers[idx]));

        let checkpoint_inscribed_tx = checkpoint_inscribed_tx_bundle.transaction();

        let rollup_params = load_test_rollup_params();
        let res = extract_checkpoint(checkpoint_inscribed_tx, &rollup_params);
        assert!(res.is_ok());
        dbg!(res.unwrap());
    }

    #[test]
    fn test_extract_withdrawal_info() {
        let headers = extract_test_headers();
        let (withdrawal_fulfillment_tx_bundle, idx) = get_withdrawal_fulfillment_tx();
        assert!(withdrawal_fulfillment_tx_bundle.verify(headers[idx]));

        let withdrawal_fulfillment_tx = withdrawal_fulfillment_tx_bundle.transaction();

        // NOTE: Although these two outputs look different, they refer to the same transaction ID.
        // The discrepancy is due to how the bytes are represented (e.g., endianness or formatting)
        // in different debug/display methods.
        dbg!(compute_txid(withdrawal_fulfillment_tx));
        dbg!(withdrawal_fulfillment_tx.compute_txid());

        let res = extract_withdrawal_info(withdrawal_fulfillment_tx);
        assert!(res.is_ok());
        dbg!(res.unwrap());
    }
}
