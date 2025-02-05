use bitcoin::{ScriptBuf, Transaction, Txid};
use strata_l1tx::envelope::parser::parse_envelope_payloads;
use strata_primitives::{
    block_credential::CredRule, bridge::OperatorIdx, l1::BitcoinAmount, params::RollupParams,
};
use strata_proofimpl_btc_blockspace::tx::compute_txid;
use strata_state::batch::{BatchCheckpoint, SignedBatchCheckpoint};

use crate::error::{BridgeProofError, BridgeRelatedTx};

// TODO: maybe read this from params or somewhere.
// NOTE: this should be a param
pub(crate) const ROLLUP_NAME: &str = "alpenstrata";

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
    let operator_id = u32::from_be_bytes(
        tx.output[1].script_pubkey.as_bytes()[2..6]
            .try_into()
            .map_err(|_| {
                BridgeProofError::TxInfoExtractionError(BridgeRelatedTx::WithdrawalFulfillment)
            })?,
    );
    let withdrawal_amount = BitcoinAmount::from_sat(tx.output[1].value.to_sat());
    let withdrawal_address = tx.output[1].script_pubkey.clone();
    Ok((operator_id, withdrawal_address, withdrawal_amount))
}

/// Returns:
///
/// 2. committed witdrawal fulfillment tx id
pub(crate) fn extract_claim_info(tx: &Transaction) -> Result<Txid, BridgeProofError> {
    // TODO: FIXME
    Ok(compute_txid(tx).into())
}
