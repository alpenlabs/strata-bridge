//! This module supplies helpers for categorizing transactions and extracting payloads from them
//! where relevant.

use std::sync::Arc;

use alpen_bridge_params::{prelude::PegOutGraphParams, sidesystem::SideSystemParams};
use bitcoin::{
    key::constants::SCHNORR_PUBLIC_KEY_SIZE, opcodes::all::OP_RETURN, OutPoint, Script,
    Transaction, Txid, XOnlyPublicKey,
};
use btc_notify::client::TxPredicate;
use strata_bridge_primitives::deposit::DepositInfo;

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

const MAGIC_BYTES: &[u8; 6] = b"strata";

fn magic_tagged_data<'a, const N: usize>(tag: &[u8; N], script: &'a Script) -> Option<&'a [u8]> {
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
    sidesystem_params: &SideSystemParams,
    pegout_graph_params: &PegOutGraphParams,
    stake_index: u32,
) -> Option<DepositInfo> {
    let deposit_request_output = tx.output.first()?;
    if deposit_request_output.value <= pegout_graph_params.deposit_amount {
        return None;
    }
    // TODO(proofofkeags): validate that the script_pubkey pays to the right operator set

    let ee_address_size = sidesystem_params.ee_addr_size;
    let (recovery_x_only_pk, el_addr) =
        magic_tagged_data(MAGIC_BYTES, &tx.output.get(1)?.script_pubkey).and_then(|meta| {
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

pub(crate) fn is_fulfillment_tx(_deposit_txid: Txid) -> TxPredicate {
    //TODO(proofofkeags): implement
    Arc::new(|_| false)
}

pub(crate) fn is_rollup_commitment(_tx: &Transaction) -> bool {
    todo!()
}
