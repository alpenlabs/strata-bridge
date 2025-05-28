use bitcoin::{consensus, ScriptBuf, Transaction, Txid};
use strata_crypto::groth16_verifier::verify_rollup_groth16_proof_receipt;
use strata_l1tx::{envelope::parser::parse_envelope_payloads, filter::types::TxFilterConfig};
use strata_primitives::{
    batch::SignedCheckpoint, bridge::OperatorIdx, l1::BitcoinAmount, params::RollupParams,
};
use strata_state::{batch::verify_signed_checkpoint_sig, chain_state::Chainstate};

use crate::error::{BridgeProofError, BridgeRelatedTx};

pub(crate) fn extract_valid_chainstate_from_checkpoint(
    tx: &Transaction,
    rollup_params: &RollupParams,
) -> Result<Chainstate, BridgeProofError> {
    let filter_config = TxFilterConfig::derive_from(rollup_params)
        .map_err(|e| BridgeProofError::InvalidParams(e.to_string()))?;

    for inp in &tx.input {
        if let Some(scr) = inp.witness.taproot_leaf_script() {
            if let Ok(payload) = parse_envelope_payloads(&scr.script.into(), &filter_config) {
                if payload.is_empty() {
                    continue;
                }

                if let Ok(checkpoint) = borsh::from_slice::<SignedCheckpoint>(payload[0].data()) {
                    if !verify_signed_checkpoint_sig(&checkpoint, &rollup_params.cred_rule) {
                        return Err(BridgeProofError::UnsatisfiedStrataCredRule);
                    }

                    let chainstate: Chainstate =
                        borsh::from_slice(checkpoint.checkpoint().sidecar().chainstate())
                            .expect("invalid chainstate");

                    if chainstate.compute_state_root()
                        != checkpoint
                            .checkpoint()
                            .batch_transition()
                            .chainstate_transition
                            .post_state_root
                    {
                        return Err(BridgeProofError::ChainStateMismatch);
                    }

                    let proof_receipt = checkpoint.checkpoint().construct_receipt();
                    if verify_rollup_groth16_proof_receipt(&proof_receipt, &rollup_params.rollup_vk)
                        .is_err()
                    {
                        return Err(BridgeProofError::InvalidStrataProof);
                    }

                    return Ok(chainstate);
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
    tag_len: usize,
    tx: &Transaction,
) -> Result<WithdrawalInfo, BridgeProofError> {
    if tx.output.len() < 2 {
        return Err(BridgeProofError::TxInfoExtractionError(
            BridgeRelatedTx::WithdrawalFulfillment(format!(
                "outputs less than 2, got: {}",
                tx.output.len()
            )),
        ));
    }

    let withdrawal_fulfillment_output = &tx.output[0];
    let withdrawal_metadata_output = &tx.output[1];

    let metadata_script = withdrawal_metadata_output.script_pubkey.as_bytes();

    const OP_RETURN_INSTRUCTION_SIZE: usize = 2; // OP_RETURN + OP_PUSHBYTES
    const OPERATOR_IDX_SIZE: usize = std::mem::size_of::<OperatorIdx>();
    const DEPOSIT_IDX_SIZE: usize = std::mem::size_of::<u32>();
    const DEPOSIT_TXID_SIZE: usize = std::mem::size_of::<Txid>();

    let expected_metadata_size: usize = OP_RETURN_INSTRUCTION_SIZE
        + tag_len
        + OPERATOR_IDX_SIZE
        + DEPOSIT_IDX_SIZE
        + DEPOSIT_TXID_SIZE;

    if metadata_script.len() != expected_metadata_size {
        return Err(BridgeProofError::TxInfoExtractionError(
            BridgeRelatedTx::WithdrawalFulfillment(format!(
                "metadata script size mismatch, expected: {}, got: {}",
                expected_metadata_size,
                metadata_script.len()
            )),
        ));
    }

    let mut offset = OP_RETURN_INSTRUCTION_SIZE + tag_len;
    let operator_idx_bytes = &metadata_script[offset..offset + OPERATOR_IDX_SIZE];

    offset += OPERATOR_IDX_SIZE;
    let deposit_idx_bytes = &metadata_script[offset..offset + DEPOSIT_IDX_SIZE];

    offset += DEPOSIT_IDX_SIZE;
    let deposit_txid_bytes = &metadata_script[offset..offset + DEPOSIT_TXID_SIZE];

    let operator_idx = u32::from_be_bytes(operator_idx_bytes.try_into().map_err(|_| {
        BridgeProofError::TxInfoExtractionError(BridgeRelatedTx::WithdrawalFulfillment(format!(
            "operator_idx bytes conversion error, expected 4 bytes, got: {}",
            operator_idx_bytes.len()
        )))
    })?);

    let deposit_idx = u32::from_be_bytes(deposit_idx_bytes.try_into().map_err(|_| {
        BridgeProofError::TxInfoExtractionError(BridgeRelatedTx::WithdrawalFulfillment(format!(
            "deposit_idx bytes conversion error, expected 4 bytes, got: {}",
            deposit_idx_bytes.len()
        )))
    })?);

    let deposit_txid: Txid = consensus::encode::deserialize(deposit_txid_bytes).map_err(|_| {
        BridgeProofError::TxInfoExtractionError(BridgeRelatedTx::WithdrawalFulfillment(format!(
            "deposit_txid bytes conversion error, expected 32 bytes, got: {}",
            deposit_txid_bytes.len()
        )))
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
    use strata_bridge_common::logging::{self, LoggerConfig};
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
        let res = extract_valid_chainstate_from_checkpoint(checkpoint_inscribed_tx, &rollup_params);
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

        let tag_size = b"alp0".len();
        let res = extract_withdrawal_info(tag_size, withdrawal_fulfillment_tx);
        assert!(
            res.is_ok(),
            "must be able to extract withdrawal info but got {:?}",
            res.unwrap_err()
        );
    }
}
