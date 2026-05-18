//! Bridge counterproof statements.

use std::num::NonZero;

use bitcoin::{
    Script, ScriptBuf, Transaction, TxOut,
    hashes::Hash,
    opcodes, relative,
    script::Instruction,
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot,
};
use secp256k1::{Message, SECP256K1};
use strata_bridge_connectors::prelude::ContestProofConnector;
use strata_btc_types::BitcoinXOnlyPublicKey;
use zkaleido::{ProofReceipt, ZkVmEnv, ZkVmEnvSsz};

use crate::{
    genesis::BridgeCounterproofGenesis,
    types::{CounterproofInput, CounterproofOutput},
};

/// Native entry point: loads genesis and runs the counterproof.
#[cfg(not(target_os = "zkvm"))]
pub fn process_counterproof(zkvm: &impl ZkVmEnv) {
    let genesis = crate::genesis::load_genesis();
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
        n_of_n_pubkey,
        proof_timelock,
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
    let game_idx_nz = NonZero::new(game_idx).expect("game_idx must be non-zero");
    verify_operator_signature(
        &tx,
        &prevouts,
        &operator_pubkey,
        game_idx_nz,
        &n_of_n_pubkey,
        relative::Height::from_height(proof_timelock),
    );

    // 3: Parse the embedded proof receipt and assert it fails verification.
    parse_and_verify_bridge_proof(&tx, genesis);

    // 4: Commit public values.
    zkvm.commit_ssz(&CounterproofOutput {
        game_idx,
        operator_pubkey,
    });
}

/// Checks that the operator really signed this bridge-proof tx by deriving
/// the `ContestProofConnector` output key and verifying against it.
fn verify_operator_signature(
    tx: &Transaction,
    prevouts: &[TxOut],
    operator_pubkey: &BitcoinXOnlyPublicKey,
    game_idx: NonZero<u32>,
    n_of_n_pubkey: &BitcoinXOnlyPublicKey,
    proof_timelock: relative::Height,
) {
    let wit_elem = tx.input[0]
        .witness
        .iter()
        .next()
        .expect("first input should carry a key-path witness");
    let tap_sig = taproot::Signature::from_slice(wit_elem)
        .expect("witness should be a taproot key-spend signature");

    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(0, &Prevouts::All(prevouts), tap_sig.sighash_type)
        .expect("sighash should compute");
    let msg = Message::from_digest_slice(&sighash.to_byte_array()).expect("sighash is 32 bytes");

    let output_key = ContestProofConnector::output_key(
        n_of_n_pubkey.to_xonly_public_key(),
        operator_pubkey.to_xonly_public_key(),
        game_idx,
        proof_timelock,
    );

    // Without this, an attacker could swap in a signature the operator made for
    // some unrelated taproot output.
    assert_eq!(
        prevouts[0].script_pubkey,
        ScriptBuf::new_p2tr_tweaked(output_key),
        "prevouts[0] is not the ContestProofConnector output for this operator + game_idx",
    );

    SECP256K1
        .verify_schnorr(&tap_sig.signature, &msg, &output_key.to_x_only_public_key())
        .expect("operator signature should verify");
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
