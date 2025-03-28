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
use strata_bridge_primitives::{deposit::DepositInfo, types::OperatorIdx};
use strata_l1tx::{envelope::parser::parse_envelope_payloads, filter::TxFilterConfig};
use strata_primitives::params::RollupParams;
use strata_state::batch::{Checkpoint, SignedCheckpoint};

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
    stake_index: u32,
) -> Option<DepositInfo> {
    let deposit_request_output = tx.output.first()?;
    if deposit_request_output.value <= pegout_graph_params.deposit_amount {
        return None;
    }
    // TODO(proofofkeags): validate that the script_pubkey pays to the right operator set

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
                .expect("Failed to parse XOnlyPublicKey");
            let el_addr =
                meta.get(SCHNORR_PUBLIC_KEY_SIZE..SCHNORR_PUBLIC_KEY_SIZE + ee_address_size)?;
            Some((recovery_x_only_pk, el_addr))
        })?;

    Some(DepositInfo::new(
        OutPoint::new(tx.compute_txid(), 0),
        stake_index,
        el_addr.to_vec(),
        deposit_request_output.value,
        recovery_x_only_pk,
        deposit_request_output.script_pubkey.clone(),
    ))
}

pub(crate) fn is_challenge(claim_txid: Txid) -> TxPredicate {
    Arc::new(move |tx| {
        tx.input
            .first()
            .map(|txin| txin.previous_output == OutPoint::new(claim_txid, 1))
            .unwrap_or(false)
            && tx.output.len() == 1
    })
}

pub(crate) fn is_disprove(post_assert_txid: Txid) -> TxPredicate {
    Arc::new(move |tx| {
        tx.input
            .first()
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
    tag: &[u8],
    operator_idx: OperatorIdx,
    deposit_idx: u32,
    deposit_txid: Txid,
    recipient: Descriptor,
) -> TxPredicate {
    let tag = tag.to_owned();
    Arc::new(move |tx| {
        let mut outputs = tx.output.iter();

        if let Ok(recipient_addr) = recipient.to_address(network) {
            if let Some(recipient_script_pubkey) =
                outputs.next().map(|output| &output.script_pubkey)
            {
                if recipient_script_pubkey != &recipient_addr.script_pubkey() {
                    return false;
                }
            }
        }

        if let Some(metadata) = outputs
            .next()
            .and_then(|output| op_return_data(&output.script_pubkey))
        {
            if !metadata.starts_with(&tag) {
                return false;
            }

            let mut offset = tag.len();

            let operator_idx = operator_idx.to_be_bytes();
            let operator_idx_size = operator_idx.len();
            if metadata.get(offset..offset + operator_idx_size) != Some(&operator_idx) {
                return false;
            }

            offset += operator_idx_size;

            let deposit_idx = deposit_idx.to_be_bytes();
            let deposit_idx_size = deposit_idx.len();
            if metadata.get(offset..offset + deposit_idx_size) != Some(&deposit_idx) {
                return false;
            }

            offset += deposit_idx_size;

            let deposit_txid = consensus::encode::serialize(&deposit_txid);
            let deposit_txid_size = deposit_txid.len();
            if metadata.get(offset..offset + deposit_txid_size) != Some(&deposit_txid) {
                return false;
            }

            return true;
        }

        false
    })
}

pub(crate) fn parse_strata_checkpoint(
    tx: &Transaction,
    rollup_params: &RollupParams,
) -> Option<Checkpoint> {
    let filter_config =
        TxFilterConfig::derive_from(rollup_params).expect("rollup params must be valid");

    if let Some(script) = tx.input[0].witness.tapscript() {
        let script = script.to_bytes();
        if let Ok(inscription) = parse_envelope_payloads(&script.into(), &filter_config) {
            if inscription.is_empty() {
                return None;
            }
            if let Ok(signed_batch_checkpoint) =
                borsh::from_slice::<SignedCheckpoint>(inscription[0].data())
            {
                return Some(signed_batch_checkpoint.into());
            }
        }
    }

    None
}
