//! TODO(proofofkeags): mod level documentation
use std::sync::Arc;

use bitcoin::{opcodes::all::OP_RETURN, OutPoint, Script, Transaction, Txid};
use btc_notify::client::TxPredicate;
use strata_bridge_primitives::types::OperatorIdx;
use strata_bridge_tx_graph::transactions::{
    claim::ClaimTx,
    prelude::{CovenantTx, PostAssertTx},
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

fn magic_tagged_data(script: &Script) -> Option<&[u8]> {
    const MAGIC_BYTES: &[u8; 6] = b"strata";
    op_return_data(script).and_then(|data| {
        if data.starts_with(MAGIC_BYTES) {
            Some(&data[MAGIC_BYTES.len()..])
        } else {
            None
        }
    })
}

const EL_ADDR_SIZE: usize = 20;

pub(crate) fn is_deposit_request(tx: &Transaction) -> bool {
    const MERKLE_PROOF_SIZE: usize = 32;
    tx.output.iter().any(|output| {
        if let Some(meta) = magic_tagged_data(&output.script_pubkey) {
            meta.len() == MERKLE_PROOF_SIZE + EL_ADDR_SIZE
        } else {
            false
        }
    })
}

pub(crate) fn is_txid(txid: Txid) -> TxPredicate {
    Arc::new(move |tx| tx.compute_txid() == txid)
}

pub(crate) fn is_challenge(claim: &ClaimTx) -> TxPredicate {
    let claim_txid = claim.psbt().unsigned_tx.compute_txid();
    Arc::new(move |tx| {
        tx.input
            .first()
            .map(|txin| txin.previous_output == OutPoint::new(claim_txid, 1))
            .unwrap_or(false)
            && tx.output.len() == 1
    })
}

pub(crate) fn is_disprove(post_assert: &PostAssertTx) -> TxPredicate {
    let post_assert_txid = post_assert.psbt().unsigned_tx.compute_txid();
    Arc::new(move |tx| {
        tx.input
            .first()
            .map(|txin| txin.previous_output == OutPoint::new(post_assert_txid, 0))
            .unwrap_or(false)
            && tx.input.len() == 2
            && tx.output.len() == 2
    })
}

pub(crate) fn is_fulfillment_tx(deposit_idx: u32, operator_idx: OperatorIdx) -> TxPredicate {
    //TODO(proofofkeags): implement
    Arc::new(|_| false)
}
