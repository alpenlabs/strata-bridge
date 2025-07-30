//! This module supplies helpers for categorizing transactions and extracting payloads from them
//! where relevant.

use std::sync::Arc;

use alpen_bridge_params::prelude::PegOutGraphParams;
use bitcoin::{
    consensus, key::constants::SCHNORR_PUBLIC_KEY_SIZE, opcodes::all::OP_RETURN, Network, OutPoint,
    Script, Transaction, Txid, XOnlyPublicKey,
};
use bitcoin_bosd::Descriptor;
use btc_notify::client::TxPredicate;
use strata_bridge_primitives::{build_context::BuildContext, types::OperatorIdx};
use strata_bridge_tx_graph::transactions::{
    claim::CHALLENGE_VOUT, deposit::DepositRequestData, prelude::POST_ASSERT_INPUT_INDEX,
};
use strata_l1tx::{envelope::parser::parse_envelope_payloads, filter::types::TxFilterConfig};
use strata_primitives::params::RollupParams;
use strata_state::batch::{verify_signed_checkpoint_sig, Checkpoint, SignedCheckpoint};
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

    let ee_address_size = sidesystem_params.address_length as usize;
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

pub(crate) fn parse_strata_checkpoint(
    tx: &Transaction,
    rollup_params: &RollupParams,
) -> Option<Checkpoint> {
    let filter_config =
        TxFilterConfig::derive_from(rollup_params).expect("rollup params must be valid");

    let script = tx.input[0].witness.taproot_leaf_script()?.script.to_bytes();

    let Ok(inscriptions) = parse_envelope_payloads(&script.into(), &filter_config) else {
        return None;
    };

    if inscriptions.is_empty() {
        return None;
    }

    let Ok(signed_checkpoint) = borsh::from_slice::<SignedCheckpoint>(inscriptions[0].data())
    else {
        return None;
    };

    let cred_rule = &rollup_params.cred_rule;
    if !verify_signed_checkpoint_sig(&signed_checkpoint, cred_rule) {
        return None;
    }

    Some(signed_checkpoint.into())
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, str::FromStr};

    use alpen_bridge_params::prelude::PegOutGraphParams;
    use bitcoin::{
        consensus, Amount, Block, Network, OutPoint, ScriptBuf, Transaction, TxOut, XOnlyPublicKey,
    };
    use bitcoin_bosd::Descriptor;
    use secp256k1::Parity;
    use strata_bridge_common::logging::{self, LoggerConfig};
    use strata_bridge_primitives::build_context::TxBuildContext;
    use strata_bridge_test_utils::prelude::{generate_txid, generate_xonly_pubkey};
    use strata_bridge_tx_graph::transactions::prelude::{
        WithdrawalFulfillment, WithdrawalMetadata,
    };
    use strata_primitives::params::RollupParams;

    use super::parse_strata_checkpoint;
    use crate::predicates::{deposit_request_info, is_fulfillment_tx};

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

    #[test]
    fn test_deposit_request_predicate() {
        logging::init(LoggerConfig::new(
            "test_deposit_request_predicate".to_string(),
        ));

        let bridge_keys = [
            "73441f2ba801b557b23c15829f4a87c02332d59a71499da1479048e6175ff4e0",
            "6bc16ede3b4b30edd4b59ab3a7209de21b468508349983e17a08910ec7a82f5f",
            "2bc0e2a6dd1c80beefa363d8baf980101d0596d914d4ee2d73e2fcaff2e72dc6",
        ]
        .iter()
        .enumerate()
        .map(|(idx, key)| {
            (
                idx as u32,
                XOnlyPublicKey::from_str(key)
                    .unwrap()
                    .public_key(Parity::Even),
            )
        })
        .collect::<BTreeMap<_, _>>();

        let maybe_drt = "\
02000000000101920a2ecd7eaa0adebb4b585552d67d7d26a7ebd7f8b43203852b041d8c2a2e910100000000fdffffff03e8\
cd9a3b00000000225120219796da38be41571aff1b3ba3f950dff6d0b4666e1607821fbd1a177d57ee800000000000000000\
3a6a38616c706e3a320d77dd6835636fb8435117eea3887e152751ee5f5fc7b87f68496e5ae44ee29f15a6b0d2e9450f392f\
88293b9fc0a5c5e1a77a3d0f0000000000225120c3464fa3e6075a23102b51ba94d784371e6ff9b1d94fcf30b4e15efbaeb8\
edff0140d5b50e414b9cf2fc7115e06e2f9da88286f8e944638b640bdcae6690a2fbef905f39ac86c28ae0a6b3e6f2a296e7\
43f4a257824f81ec1bfefe827633958b523a16090000\
";
        let maybe_drt: Transaction = consensus::encode::deserialize_hex(maybe_drt).unwrap();

        let sidesystem_params =
            std::fs::read_to_string("../../test-data/rollup_params.json").unwrap();
        let sidesystem_params: RollupParams = serde_json::from_str(&sidesystem_params).unwrap();
        let pegout_graph_params = PegOutGraphParams::default();
        let build_context = TxBuildContext::new(Network::Signet, bridge_keys.into(), 0);
        let random_stake_index = 10;

        let Some(deposit_request_data) = deposit_request_info(
            &maybe_drt,
            &sidesystem_params,
            &pegout_graph_params,
            &build_context,
            random_stake_index,
        ) else {
            panic!("failed to parse deposit request data");
        };

        assert_eq!(
            deposit_request_data.deposit_request_outpoint().txid,
            maybe_drt.compute_txid(),
            "deposit request txid must match"
        );

        assert_eq!(
            deposit_request_data.stake_index(),
            random_stake_index,
            "stake index must match"
        );

        let expected_el_address = vec![
            0xe2, 0x9f, 0x15, 0xa6, 0xb0, 0xd2, 0xe9, 0x45, 0xf, 0x39, 0x2f, 0x88, 0x29, 0x3b,
            0x9f, 0xc0, 0xa5, 0xc5, 0xe1, 0xa7,
        ];
        assert_eq!(
            deposit_request_data.el_address(),
            expected_el_address,
            "execution environment address must match"
        );

        let expected_output_amount = Amount::from_sat(1_000_001_000);
        assert_eq!(
            *deposit_request_data.total_amount(),
            expected_output_amount,
            "deposit amount must match"
        );

        let expected_recovery_x_only_pk = XOnlyPublicKey::from_str(
            "3a320d77dd6835636fb8435117eea3887e152751ee5f5fc7b87f68496e5ae44e",
        )
        .unwrap();
        assert_eq!(
            *deposit_request_data.x_only_public_key(),
            expected_recovery_x_only_pk,
            "recovery x-only public key must match"
        );
    }
}
