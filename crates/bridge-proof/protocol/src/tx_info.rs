use bitcoin::{consensus, ScriptBuf, Transaction, Txid};
use strata_l1tx::{envelope::parser::parse_envelope_payloads, filter::TxFilterConfig};
use strata_primitives::{
    block_credential::CredRule, bridge::OperatorIdx, l1::BitcoinAmount, params::RollupParams,
};
use strata_state::batch::{BatchCheckpoint, SignedBatchCheckpoint};

use crate::error::{BridgeProofError, BridgeRelatedTx};

pub(crate) fn extract_checkpoint(
    tx: &Transaction,
    rollup_params: &RollupParams,
) -> Result<BatchCheckpoint, BridgeProofError> {
    let filter_config = TxFilterConfig::derive_from(rollup_params)
        .map_err(|e| BridgeProofError::InvalidParams(e.to_string()))?;

    for inp in &tx.input {
        if let Some(scr) = inp.witness.tapscript() {
            if let Ok(payload) = parse_envelope_payloads(&scr.into(), &filter_config) {
                if payload.is_empty() {
                    continue;
                }

                if let Ok(checkpoint) =
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WithdrawalInfo {
    pub(crate) operator_idx: OperatorIdx,
    pub(crate) deposit_idx: u32,
    pub(crate) deposit_txid: Txid,
    pub(crate) withdrawal_address: ScriptBuf,
    pub(crate) withdrawal_amount: BitcoinAmount,
}

// TODO: make this standard
pub(crate) fn extract_withdrawal_info(
    tx: &Transaction,
) -> Result<WithdrawalInfo, BridgeProofError> {
    if tx.output.len() < 2 {
        return Err(BridgeProofError::TxInfoExtractionError(
            BridgeRelatedTx::WithdrawalFulfillment,
        ));
    }

    let withdrawal_fulfillment_output = &tx.output[0];
    let withdrawal_metadata_output = &tx.output[1];

    let metadata_script = withdrawal_metadata_output.script_pubkey.as_bytes();
    const EXPECTED_METADATA_SIZE: usize = 2 + 4 + 4 + 32; // OP_RETURN + OP_PUSHBYTES + operator_id + deposit_id + deposit_txid
    if metadata_script.len() != EXPECTED_METADATA_SIZE {
        return Err(BridgeProofError::TxInfoExtractionError(
            BridgeRelatedTx::WithdrawalFulfillment,
        ));
    }

    let operator_idx_bytes = &metadata_script[2..6];

    let deposit_idx_bytes = &metadata_script[6..10];
    let deposit_txid_bytes = &metadata_script[10..42];

    let operator_idx = u32::from_be_bytes(operator_idx_bytes.try_into().map_err(|_| {
        BridgeProofError::TxInfoExtractionError(BridgeRelatedTx::WithdrawalFulfillment)
    })?);

    let deposit_idx = u32::from_be_bytes(deposit_idx_bytes.try_into().map_err(|_| {
        BridgeProofError::TxInfoExtractionError(BridgeRelatedTx::WithdrawalFulfillment)
    })?);

    let deposit_txid: Txid = consensus::encode::deserialize(deposit_txid_bytes).map_err(|_| {
        BridgeProofError::TxInfoExtractionError(BridgeRelatedTx::WithdrawalFulfillment)
    })?;

    let withdrawal_amount = BitcoinAmount::from_sat(withdrawal_fulfillment_output.value.to_sat());
    let withdrawal_address = withdrawal_fulfillment_output.script_pubkey.clone();

    Ok(WithdrawalInfo {
        operator_idx,
        deposit_idx,
        deposit_txid,
        withdrawal_address,
        withdrawal_amount,
    })
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash;
    use prover_test_utils::{
        extract_test_headers, get_strata_checkpoint_tx, get_withdrawal_fulfillment_tx,
        load_test_rollup_params,
    };
    use strata_common::logging::{self, LoggerConfig};
    use strata_proofimpl_btc_blockspace::tx::compute_txid;
    use tracing::info;

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
        assert!(
            res.is_ok(),
            "must be able to extract checkpoint but got: {:?}",
            res.unwrap_err()
        );
    }

    #[test]
    fn test_extract_withdrawal_info() {
        logging::init(LoggerConfig::new(
            "test-extract-withdrawal-info".to_string(),
        ));
        let headers = extract_test_headers();
        let (withdrawal_fulfillment_tx_bundle, idx) = get_withdrawal_fulfillment_tx();
        assert!(withdrawal_fulfillment_tx_bundle.verify(headers[idx]));

        let withdrawal_fulfillment_tx = withdrawal_fulfillment_tx_bundle.transaction();

        // NOTE: Although these two outputs look different, they refer to the same transaction ID.
        // The discrepancy is due to how the bytes are represented (e.g., endianness or formatting)
        // in different debug/display methods.
        info!(txid = ?compute_txid(withdrawal_fulfillment_tx), "computed txid using custom impl");
        info!(txid = %withdrawal_fulfillment_tx.compute_txid(), "computed txid using rust-bitcoin impl");

        let custom_computed_txid = compute_txid(withdrawal_fulfillment_tx);
        let rust_bitcoin_computed_txid = withdrawal_fulfillment_tx.compute_txid();

        assert_eq!(
            custom_computed_txid.0,
            rust_bitcoin_computed_txid.to_raw_hash().to_byte_array(),
            "custom computed txid must match rust-bitcoin computed txid"
        );

        let res = extract_withdrawal_info(withdrawal_fulfillment_tx);
        assert!(
            res.is_ok(),
            "must be able to extract withdrawal info but got {:?}",
            res.unwrap_err()
        );
    }
}
