//! This module supplies helpers for categorizing transactions and extracting payloads from them
//! where relevant.
use std::sync::Arc;

use bitcoin::{
    hashes::Hash, opcodes::all::OP_RETURN, OutPoint, Script, TapNodeHash, Transaction, Txid,
};
use btc_notify::client::TxPredicate;
use strata_bridge_primitives::{
    deposit::DepositInfo,
    params::{
        strata::{EL_ADDR_SIZE, MERKLE_PROOF_SIZE},
        tx::BRIDGE_DENOMINATION,
    },
};

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

pub(crate) fn deposit_request_info(tx: &Transaction) -> Option<DepositInfo> {
    let deposit_request_output = tx.output.first()?;
    if deposit_request_output.value <= BRIDGE_DENOMINATION {
        return None;
    }
    // TODO(proofofkeags): validate that the script_pubkey pays to the right operator set

    let (take_back_leaf_hash, el_addr) =
        magic_tagged_data(MAGIC_BYTES, &tx.output.get(1)?.script_pubkey).and_then(|meta| {
            if meta.len() != MERKLE_PROOF_SIZE + EL_ADDR_SIZE {
                return None;
            }
            let take_back_leaf_hash = meta.get(..MERKLE_PROOF_SIZE)?;
            let el_addr = meta.get(MERKLE_PROOF_SIZE..MERKLE_PROOF_SIZE + EL_ADDR_SIZE)?;
            Some((take_back_leaf_hash, el_addr))
        })?;

    Some(DepositInfo::new(
        OutPoint::new(tx.compute_txid(), 0),
        el_addr.to_vec(),
        deposit_request_output.value,
        TapNodeHash::from_slice(take_back_leaf_hash).unwrap(),
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
