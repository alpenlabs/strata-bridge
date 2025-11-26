//! This module supplies helpers for categorizing transactions and extracting payloads from them
//! where relevant.

use std::sync::Arc;

use alpen_bridge_params::prelude::PegOutGraphParams;
use bitcoin::{
    consensus, key::constants::SCHNORR_PUBLIC_KEY_SIZE, opcodes::all::OP_RETURN, Network, OutPoint,
    Script, Transaction, Txid, XOnlyPublicKey,
};
use bitcoin_bosd::Descriptor;
use btc_tracker::TxPredicate;
use strata_bridge_primitives::{build_context::BuildContext, types::OperatorIdx};
use strata_bridge_tx_graph::transactions::{
    claim::CHALLENGE_VOUT, deposit::DepositRequestData, prelude::POST_ASSERT_INPUT_INDEX,
};
use strata_checkpoint_types::Checkpoint;
use strata_params::RollupParams;
use tracing::warn;

fn op_return_data(script: &Script) -> Option<&[u8]> {
    let mut instructions = script.instructions();
    if let Some(Ok(bitcoin::script::Instruction::Op(OP_RETURN))) = instructions.next() {
        // NOOP
    } else {
        return None;
    }

    if let Some(Ok(bitcoin::script::Instruction::PushBytes(bytes))) = instructions.next() {
        Some(bytes.as_bytes())
    } else {
        None
    }
}

fn magic_tagged_data<'script>(tag: &[u8], script: &'script Script) -> Option<&'script [u8]> {
    op_return_data(script).and_then(|data| {
        if data.starts_with(tag) {
            Some(&data[tag.len()..])
        } else {
            None
        }
    })
}

pub(crate) fn deposit_request_info(
    tx: &Transaction,
    sidesystem_params: &RollupParams,
    pegout_graph_params: &PegOutGraphParams,
    build_context: &impl BuildContext,
    stake_index: u32,
) -> Option<DepositRequestData> {
    let deposit_request_output = tx.output.first()?;
    if deposit_request_output.value <= pegout_graph_params.deposit_amount {
        return None;
    }

    let ee_address_size = sidesystem_params.max_address_length as usize;
    let tag = pegout_graph_params.tag.as_bytes();

    let (recovery_x_only_pk, el_addr) = magic_tagged_data(tag, &tx.output.get(1)?.script_pubkey)
        .and_then(|meta| {
            if meta.len() != SCHNORR_PUBLIC_KEY_SIZE + ee_address_size {
                return None;
            }
            let recovery_x_only_pk = meta.get(..SCHNORR_PUBLIC_KEY_SIZE)?;
            // TODO: handle error variant and get rid of expect.
            let recovery_x_only_pk = XOnlyPublicKey::from_slice(recovery_x_only_pk)
                .expect("failed to parse XOnlyPublicKey");
            let el_addr =
                meta.get(SCHNORR_PUBLIC_KEY_SIZE..SCHNORR_PUBLIC_KEY_SIZE + ee_address_size)?;
            Some((recovery_x_only_pk, el_addr))
        })?;

    let deposit_request_data = DepositRequestData::new(
        OutPoint::new(tx.compute_txid(), 0),
        stake_index,
        el_addr.to_vec(),
        deposit_request_output.value,
        recovery_x_only_pk,
        deposit_request_output.script_pubkey.clone(),
    );

    // Regenerate the P2TR address from the OP_RETURN data, for now the spend info does all the
    // necessary validations.
    deposit_request_data
        .validate(build_context, pegout_graph_params.refund_delay)
        .map_err(|e| {
            warn!(err=%e, txid=%tx.compute_txid(), "DRT failed validation");
            None::<DepositRequestData>
        })
        .ok()?;

    Some(deposit_request_data)
}

pub(crate) fn is_challenge(claim_txid: Txid) -> TxPredicate {
    Arc::new(move |tx| {
        tx.input
            .first()
            .map(|txin| txin.previous_output == OutPoint::new(claim_txid, CHALLENGE_VOUT))
            .unwrap_or(false)
            && tx.output.len() == 1
    })
}

pub(crate) fn is_disprove(post_assert_txid: Txid) -> TxPredicate {
    Arc::new(move |tx| {
        tx.input
            .get(POST_ASSERT_INPUT_INDEX)
            .map(|txin| txin.previous_output == OutPoint::new(post_assert_txid, 0))
            .unwrap_or(false)
            && tx.input.len() == 2
            && tx.output.len() == 2
    })
}

/// Creates a filter predicate that checks if a transaction is a valid withdrawal fulfillment
/// transaction.
pub(crate) fn is_fulfillment_tx(
    network: Network,
    pegout_graph_params: &PegOutGraphParams,
    operator_idx: OperatorIdx,
    deposit_idx: u32,
    deposit_txid: Txid,
    recipient: Descriptor,
) -> TxPredicate {
    let PegOutGraphParams {
        tag,
        deposit_amount,
        operator_fee,
        ..
    } = pegout_graph_params;
    let tag = tag.as_bytes().to_owned();
    let output_amount = *deposit_amount - *operator_fee;

    Arc::new(move |tx| {
        let first_output_ok = match (recipient.to_address(network), tx.output.first()) {
            (Ok(recipient_addr), Some(output)) => {
                output.script_pubkey == recipient_addr.script_pubkey()
                    && output.value == output_amount
            }
            _ => false,
        };

        let second_output_ok = if let Some(metadata) = tx
            .output
            .get(1)
            .and_then(|output| op_return_data(&output.script_pubkey))
        {
            let begin_with_tag = metadata.starts_with(&tag);

            let operator_id_offset = tag.len();

            let operator_idx = operator_idx.to_be_bytes();
            let operator_idx_size = operator_idx.len();
            let operator_id_valid = metadata
                .get(operator_id_offset..operator_id_offset + operator_idx_size)
                == Some(&operator_idx);

            let deposit_id_offset = operator_id_offset + operator_idx_size;

            let deposit_idx = deposit_idx.to_be_bytes();
            let deposit_idx_size = deposit_idx.len();
            let deposit_id_valid = metadata
                .get(deposit_id_offset..deposit_id_offset + deposit_idx_size)
                == Some(&deposit_idx);

            let deposit_txid_offset = deposit_id_offset + deposit_idx_size;

            let deposit_txid = consensus::encode::serialize(&deposit_txid);
            let deposit_txid_size = deposit_txid.len();
            let deposit_txid_valid = metadata
                .get(deposit_txid_offset..deposit_txid_offset + deposit_txid_size)
                == Some(&deposit_txid);

            begin_with_tag && operator_id_valid && deposit_id_valid && deposit_txid_valid
        } else {
            false
        };

        first_output_ok && second_output_ok
    })
}

/// Parses a Strata checkpoint from the given transaction.
///
/// TODO(ASM, @MdTeach): This is a temporary placeholder implementation and
/// will be replaced once ASM integration is completed.
pub(crate) const fn parse_strata_checkpoint(
    _tx: &Transaction,
    _rollup_params: &RollupParams,
) -> Option<Checkpoint> {
    None
}

#[cfg(test)]
mod tests {
    use alpen_bridge_params::prelude::PegOutGraphParams;
    use bitcoin::{Amount, Block, OutPoint, ScriptBuf, TxOut};
    use bitcoin_bosd::Descriptor;
    use strata_bridge_test_utils::prelude::{generate_txid, generate_xonly_pubkey};
    use strata_bridge_tx_graph::transactions::prelude::{
        WithdrawalFulfillment, WithdrawalMetadata,
    };
    use strata_params::RollupParams;

    use super::parse_strata_checkpoint;
    use crate::predicates::is_fulfillment_tx;

    #[test]
    fn test_fulfillment_predicate() {
        let peg_out_graph_params = PegOutGraphParams::default();

        let metadata = WithdrawalMetadata {
            tag: peg_out_graph_params.tag,
            operator_idx: 1,
            deposit_idx: 2,
            deposit_txid: generate_txid(),
        };

        let sender_outpoints = vec![OutPoint {
            txid: generate_txid(),
            vout: 0,
        }];
        let amount = peg_out_graph_params.deposit_amount - peg_out_graph_params.operator_fee;
        let change = TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![1u8; 32]),
        };
        let test_key = generate_xonly_pubkey().serialize();
        let recipient_desc = Descriptor::new_p2tr(&test_key).unwrap();

        let withdrawal_fulfillment_tx = WithdrawalFulfillment::new(
            metadata.clone(),
            sender_outpoints,
            amount,
            Some(change),
            recipient_desc.clone(),
        );

        let mut withdrawal_fulfillment_tx = withdrawal_fulfillment_tx.tx();

        let network = bitcoin::Network::Regtest;
        let fulfillment_filter = is_fulfillment_tx(
            network,
            &peg_out_graph_params,
            metadata.operator_idx,
            metadata.deposit_idx,
            metadata.deposit_txid,
            recipient_desc,
        );

        assert!(
            fulfillment_filter(&withdrawal_fulfillment_tx),
            "must identify valid fulfillment tx"
        );

        withdrawal_fulfillment_tx.output[0].value = Amount::from_sat(10);
        assert!(
            !fulfillment_filter(&withdrawal_fulfillment_tx),
            "must not identify invalid fulfillment tx"
        );
    }

    #[test]
    #[ignore = "skipping this since we don't do checkpoint parsing until ASM integration"]
    fn test_checkpoint_predicate() {
        let rollup_params = std::fs::read_to_string("../../test-data/rollup_params.json").unwrap();
        let rollup_params: RollupParams = serde_json::from_str(&rollup_params).unwrap();

        let blocks_bytes = std::fs::read("../../test-data/blocks.bin").unwrap();
        let blocks: Vec<Block> = bincode::deserialize(&blocks_bytes).unwrap();

        // these values are known during test-data generation
        let block_height = 233;
        let tx_index = 2;

        let strata_checkpoint_tx = blocks
            .iter()
            .find(|block| block.bip34_block_height().unwrap() == block_height)
            .expect("expected height with strata checkpoint must exist")
            .txdata
            .get(tx_index)
            .expect("expected index of checkpoint must exist in txdata");

        assert!(
            parse_strata_checkpoint(strata_checkpoint_tx, &rollup_params).is_some(),
            "must be able to parse valid strata checkpoint tx"
        );
    }
}
