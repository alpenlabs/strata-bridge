use bitcoin::{Transaction, Txid};
use borsh::BorshDeserialize;
use strata_l1tx::envelope::parser::parse_envelope_data;
use strata_primitives::{
    block_credential::CredRule,
    bridge::OperatorIdx,
    l1::{BitcoinAmount, XOnlyPk},
};
use strata_proofimpl_btc_blockspace::tx::compute_txid;
use strata_state::batch::{BatchCheckpoint, SignedBatchCheckpoint};

use crate::error::{BridgeProofError, BridgeRelatedTx};

// TODO: maybe read this from params or somewhere.
// NOTE: this should be a param
pub(crate) const ROLLUP_NAME: &str = "alpenstrata";

pub(crate) fn extract_checkpoint(
    tx: &Transaction,
    cred_rule: &CredRule,
) -> Result<BatchCheckpoint, BridgeProofError> {
    for inp in &tx.input {
        if let Some(scr) = inp.witness.tapscript() {
            if let Ok(payload) = parse_envelope_data(&scr.into(), ROLLUP_NAME) {
                if let Ok(checkpoint) = borsh::from_slice::<SignedBatchCheckpoint>(payload.data()) {
                    if let CredRule::SchnorrKey(seq_pubkey) = cred_rule {
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
) -> Result<(OperatorIdx, XOnlyPk, BitcoinAmount), BridgeProofError> {
    let operator_id = u32::from_be_bytes(
        tx.output[1].script_pubkey.as_bytes()[2..6]
            .try_into()
            .map_err(|_| {
                BridgeProofError::TxInfoExtractionError(BridgeRelatedTx::WithdrawalFulfillment)
            })?,
    );
    let withdrawal_amount = BitcoinAmount::from_sat(tx.output[1].value.to_sat());
    let withdrawal_address = XOnlyPk::try_from_slice(&tx.output[1].script_pubkey.as_bytes()[2..])
        .map_err(|_| {
        BridgeProofError::TxInfoExtractionError(BridgeRelatedTx::WithdrawalFulfillment)
    })?;
    Ok((operator_id, withdrawal_address, withdrawal_amount))
}

/// Returns:
///
/// 2. committed witdrawal fulfillment tx id
pub(crate) fn extract_claim_info(tx: &Transaction) -> Result<Txid, BridgeProofError> {
    // TODO: FIXME
    Ok(compute_txid(tx).into())
}
