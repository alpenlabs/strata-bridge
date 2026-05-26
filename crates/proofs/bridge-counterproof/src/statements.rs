//! Bridge counterproof statements.

use bitcoin::{
    Script, Transaction, TxOut, opcodes, script::Instruction, sighash::TapSighashType, taproot,
};
use strata_btc_types::BitcoinXOnlyPublicKey;
use zkaleido::{ProofReceipt, ZkVmEnv, ZkVmEnvSsz};

#[cfg(not(target_os = "zkvm"))]
use crate::genesis::load_genesis;
use crate::types::{BridgeCounterproofGenesis, CounterproofInput, CounterproofOutput};

/// Native entry point: loads genesis and runs the counterproof.
#[cfg(not(target_os = "zkvm"))]
pub fn process_counterproof(zkvm: &impl ZkVmEnv) {
    let genesis = load_genesis();
    process_counterproof_inner(zkvm, &genesis);
}

/// zkVM entry point: runs the counterproof.
#[cfg(target_os = "zkvm")]
pub fn process_counterproof(zkvm: &impl ZkVmEnv, genesis: BridgeCounterproofGenesis) {
    process_counterproof_inner(zkvm, &genesis);
}

/// Reads the SSZ input, verifies it against `genesis`, and commits the output.
///
/// Steps:
/// 1. Decode `CounterproofInput`.
/// 2. Verify the operator's schnorr signature on `bridge_proof_tx`.
/// 3. Check the embedded bridge proof fails verification.
/// 4. Commit `CounterproofOutput`.
fn process_counterproof_inner(zkvm: &impl ZkVmEnv, genesis: &BridgeCounterproofGenesis) {
    // 1: Decode CounterproofInput.
    let CounterproofInput {
        game_idx,
        operator_pubkey,
        bridge_proof_tx,
        bridge_proof_tx_prevouts,
    } = zkvm.read_ssz();
    let tx: Transaction = (&bridge_proof_tx)
        .try_into()
        .expect("bridge_proof_tx must consensus-decode into a Transaction");
    let prevouts: Vec<TxOut> = bridge_proof_tx_prevouts
        .into_iter()
        .map(TxOut::from)
        .collect();
    assert_eq!(
        tx.input.len(),
        prevouts.len(),
        "prevouts must match inputs 1:1",
    );

    // 2: Verify the operator signed the bridge-proof tx.
    verify_operator_signature(&tx, &prevouts, &operator_pubkey, game_idx);

    // 3: Parse the embedded proof receipt and assert it fails verification.
    parse_and_verify_bridge_proof(&tx, genesis);

    // 4: Commit public values.
    zkvm.commit_ssz(&CounterproofOutput {
        game_idx,
        operator_pubkey,
    });
}

/// Verifies the schnorr signature in `tx.input[0]` against
/// `bip340_tweak(operator_pubkey, game_idx)` over the BIP-341 key-path sighash.
///
/// no-op for now; the body will land in a follow-up.
// TODO: <https://alpenlabs.atlassian.net/browse/STR-1981>
const fn verify_operator_signature(
    _tx: &Transaction,
    _prevouts: &[TxOut],
    _operator_pubkey: &BitcoinXOnlyPublicKey,
    _game_idx: u32,
) {
}

/// Pulls the `ProofReceipt` out of `tx.output[0]`'s OP_RETURN and panics if
/// it actually verifies against `genesis.bridge_proof_vk` — a valid bridge
/// proof is the one thing we can't refute.
///
/// If the tx doesn't look like a bridge-proof tx we skip the Groth16
/// check entirely: the operator's signature has already been authenticated,
/// and signing an off-shape tx is misbehavior on its own.
fn parse_and_verify_bridge_proof(tx: &Transaction, genesis: &BridgeCounterproofGenesis) {
    let wit_elem = tx.input[0]
        .witness
        .iter()
        .next()
        .expect("txin[0] witness checked in verify_operator_signature");
    let tap_sig =
        taproot::Signature::from_slice(wit_elem).expect("valid taproot key-spend signature");

    if tap_sig.sighash_type != TapSighashType::Default {
        return;
    }
    let Some(first_out) = tx.output.first() else {
        return;
    };
    let Some(data) = extract_op_return_payload(&first_out.script_pubkey) else {
        return;
    };
    let Ok(receipt) = borsh::from_slice::<ProofReceipt>(data) else {
        return;
    };

    assert!(
        genesis
            .bridge_proof_vk
            .verify_claim_witness(
                receipt.public_values().as_bytes(),
                receipt.proof().as_bytes(),
            )
            .is_err(),
        "embedded bridge proof verified; cannot refute it",
    );
}

/// Extracts the pushed payload of an `OP_RETURN <PushBytes>` script.
fn extract_op_return_payload(spk: &Script) -> Option<&[u8]> {
    let mut it = spk.instructions();
    let first = it.next()?.ok()?;
    let second = it.next()?.ok()?;
    if !matches!(first, Instruction::Op(op) if op == opcodes::all::OP_RETURN) {
        return None;
    }
    let Instruction::PushBytes(bytes) = second else {
        return None;
    };
    if it.next().is_some() {
        return None;
    }
    Some(bytes.as_bytes())
}
