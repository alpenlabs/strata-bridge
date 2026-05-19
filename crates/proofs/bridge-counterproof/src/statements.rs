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

#[cfg(test)]
mod tests {
    use bitcoin::{
        Amount, Network, TxIn, Witness, absolute,
        blockdata::transaction::Version,
        opcodes::all::{OP_PUSHNUM_1, OP_RETURN},
        script::{Builder, PushBytesBuf},
    };
    use secp256k1::{Keypair, XOnlyPublicKey};
    use ssz::{Decode, Encode};
    use strata_bridge_connectors::{Connector, prelude::TimelockedSpendPath};
    use strata_predicate::PredicateKey;
    use zkaleido::{Proof, PublicValues};
    use zkaleido_native_adapter::NativeMachine;

    use super::*;
    use crate::types::{BitcoinTxOut, RawBitcoinTx};

    const GAME_IDX: u32 = 7;
    const PROOF_TIMELOCK: u16 = 100;

    fn taproot_witness(sighash_type: TapSighashType) -> Witness {
        let mut signature = vec![1u8; 64];
        if sighash_type != TapSighashType::Default {
            signature.push(sighash_type as u8);
        }
        Witness::from_slice(&[signature])
    }

    fn txout(script_pubkey: ScriptBuf) -> TxOut {
        TxOut {
            value: Amount::from_sat(0),
            script_pubkey,
        }
    }

    fn tx_with_outputs(output: Vec<TxOut>) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                witness: taproot_witness(TapSighashType::Default),
                ..Default::default()
            }],
            output,
        }
    }

    fn op_return_script(data: Vec<u8>) -> ScriptBuf {
        let payload = PushBytesBuf::try_from(data).unwrap();
        ScriptBuf::new_op_return(payload)
    }

    fn proof_receipt_tx() -> Transaction {
        let receipt = ProofReceipt::new(Proof::new(vec![]), PublicValues::new(vec![]));
        tx_with_outputs(vec![txout(op_return_script(
            borsh::to_vec(&receipt).unwrap(),
        ))])
    }

    fn deterministic_keypair(seed: u8) -> Keypair {
        Keypair::from_seckey_slice(SECP256K1, &[seed; 32]).expect("seed produces valid secret key")
    }

    fn xonly(kp: &Keypair) -> XOnlyPublicKey {
        kp.x_only_public_key().0
    }

    fn contest_connector(
        operator: XOnlyPublicKey,
        n_of_n: XOnlyPublicKey,
        game_idx: NonZero<u32>,
        proof_timelock: relative::Height,
    ) -> ContestProofConnector {
        ContestProofConnector::new(
            Network::Regtest,
            n_of_n,
            operator,
            game_idx,
            proof_timelock,
            Amount::ZERO,
        )
    }

    /// Builds an unsigned 1-input / 1-output contest-proof tx whose `prevouts[0]`
    /// is `connector`'s P2TR. The first output is an OP_RETURN holding an
    /// empty `ProofReceipt`.
    fn unsigned_contest_tx(connector: &ContestProofConnector) -> (Transaction, Vec<TxOut>) {
        let prevouts = vec![txout(connector.script_pubkey())];

        let receipt = ProofReceipt::new(Proof::new(vec![]), PublicValues::new(vec![]));
        let tx = Transaction {
            version: Version::TWO,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                witness: Witness::new(),
                ..Default::default()
            }],
            output: vec![txout(op_return_script(borsh::to_vec(&receipt).unwrap()))],
        };
        (tx, prevouts)
    }

    /// Signs `tx.input[0]` under `connector`'s output-key secret and writes
    /// the resulting key-path witness into the tx.
    fn sign_input_zero(
        tx: &mut Transaction,
        prevouts: &[TxOut],
        operator_kp: &Keypair,
        connector: &ContestProofConnector,
        game_idx: NonZero<u32>,
    ) {
        // `connector.get_signing_info` produces a sighash + merkle-root tweak;
        // `SigningInfo::sign` then applies the tap-tweak and schnorr-signs.
        // We still have to pre-apply the per-game scalar to get the internal key.
        let internal_kp = operator_kp
            .add_xonly_tweak(
                SECP256K1,
                &ContestProofConnector::operator_key_tweak(game_idx),
            )
            .expect("game-idx tweak is valid");

        let signing_info = connector.get_signing_info(
            &mut SighashCache::new(&*tx),
            Prevouts::All(prevouts),
            TimelockedSpendPath::Normal,
            0,
        );
        let signature = signing_info.sign(&internal_kp);

        tx.input[0].witness = Witness::p2tr_key_spend(&taproot::Signature {
            signature,
            sighash_type: TapSighashType::Default,
        });
    }

    /// Builds a fully-signed canonical contest-proof tx + prevouts.
    fn signed_contest_fixture() -> (Transaction, Vec<TxOut>, Keypair, Keypair) {
        let operator_kp = deterministic_keypair(1);
        let n_of_n_kp = deterministic_keypair(2);
        let game_idx = NonZero::new(GAME_IDX).unwrap();
        let proof_timelock = relative::Height::from_height(PROOF_TIMELOCK);
        let connector = contest_connector(
            xonly(&operator_kp),
            xonly(&n_of_n_kp),
            game_idx,
            proof_timelock,
        );

        let (mut tx, prevouts) = unsigned_contest_tx(&connector);
        sign_input_zero(&mut tx, &prevouts, &operator_kp, &connector, game_idx);
        (tx, prevouts, operator_kp, n_of_n_kp)
    }

    /// Wraps the unsigned components of a `CounterproofInput` in SSZ-wire form.
    fn counterproof_input_from(
        tx: Transaction,
        prevouts: Vec<TxOut>,
        operator_kp: &Keypair,
        n_of_n_kp: &Keypair,
    ) -> CounterproofInput {
        CounterproofInput {
            game_idx: GAME_IDX,
            operator_pubkey: xonly(operator_kp).into(),
            n_of_n_pubkey: xonly(n_of_n_kp).into(),
            proof_timelock: PROOF_TIMELOCK,
            bridge_proof_tx: RawBitcoinTx::from(tx),
            bridge_proof_tx_prevouts: prevouts.into_iter().map(BitcoinTxOut::from).collect(),
        }
    }

    fn canonical_counterproof_input() -> CounterproofInput {
        let (tx, prevouts, operator_kp, n_of_n_kp) = signed_contest_fixture();
        counterproof_input_from(tx, prevouts, &operator_kp, &n_of_n_kp)
    }

    /// Drives `process_counterproof_inner` through a `NativeMachine`.
    fn run_counterproof(
        input: CounterproofInput,
        bridge_proof_vk: PredicateKey,
    ) -> CounterproofOutput {
        let mut machine = NativeMachine::new();
        machine.write_slice(input.as_ssz_bytes());
        process_counterproof_inner(&machine, &BridgeCounterproofGenesis { bridge_proof_vk });
        CounterproofOutput::from_ssz_bytes(&machine.state.borrow().output).unwrap()
    }

    #[test]
    fn op_return_shape_determines_payload() {
        let extra_payload = PushBytesBuf::try_from(vec![1u8]).unwrap();
        let cases = [
            (op_return_script(vec![1u8, 2, 3]), Some(vec![1u8, 2, 3])),
            (ScriptBuf::new(), None),
            (Builder::new().push_opcode(OP_PUSHNUM_1).into_script(), None),
            (Builder::new().push_opcode(OP_RETURN).into_script(), None),
            (
                Builder::new()
                    .push_opcode(OP_RETURN)
                    .push_slice(extra_payload)
                    .push_opcode(OP_PUSHNUM_1)
                    .into_script(),
                None,
            ),
        ];

        for (script_pubkey, expected) in cases {
            let result = extract_op_return_payload(&script_pubkey).map(<[u8]>::to_vec);

            assert_eq!(result, expected);
        }
    }

    #[test]
    fn non_refutable_inputs_skip_bridge_proof_verification() {
        let mut non_default_sighash_tx = proof_receipt_tx();
        non_default_sighash_tx.input[0].witness = taproot_witness(TapSighashType::All);
        let cases = [
            non_default_sighash_tx,
            tx_with_outputs(vec![]),
            tx_with_outputs(vec![txout(ScriptBuf::new())]),
            tx_with_outputs(vec![txout(op_return_script(vec![1u8, 2, 3]))]),
        ];
        let genesis = BridgeCounterproofGenesis {
            bridge_proof_vk: PredicateKey::always_accept(),
        };

        for tx in cases {
            parse_and_verify_bridge_proof(&tx, &genesis);
        }
    }

    #[test]
    fn invalid_embedded_bridge_proof_returns() {
        let tx = proof_receipt_tx();
        let genesis = BridgeCounterproofGenesis {
            bridge_proof_vk: PredicateKey::never_accept(),
        };

        parse_and_verify_bridge_proof(&tx, &genesis);
    }

    #[test]
    #[should_panic(expected = "embedded bridge proof verified; cannot refute it")]
    fn valid_embedded_bridge_proof_panics() {
        let tx = proof_receipt_tx();
        let genesis = BridgeCounterproofGenesis {
            bridge_proof_vk: PredicateKey::always_accept(),
        };

        parse_and_verify_bridge_proof(&tx, &genesis);
    }

    #[test]
    fn verify_operator_signature_accepts_canonical_signed_tx() {
        let (tx, prevouts, operator_kp, n_of_n_kp) = signed_contest_fixture();

        verify_operator_signature(
            &tx,
            &prevouts,
            &xonly(&operator_kp).into(),
            NonZero::new(GAME_IDX).unwrap(),
            &xonly(&n_of_n_kp).into(),
            relative::Height::from_height(PROOF_TIMELOCK),
        );
    }

    #[test]
    #[should_panic(expected = "prevouts[0] is not the ContestProofConnector output")]
    fn verify_operator_signature_rejects_wrong_operator_pubkey() {
        let (tx, prevouts, _operator_kp, n_of_n_kp) = signed_contest_fixture();
        let other = deterministic_keypair(9);

        verify_operator_signature(
            &tx,
            &prevouts,
            &xonly(&other).into(),
            NonZero::new(GAME_IDX).unwrap(),
            &xonly(&n_of_n_kp).into(),
            relative::Height::from_height(PROOF_TIMELOCK),
        );
    }

    #[test]
    #[should_panic(expected = "prevouts[0] is not the ContestProofConnector output")]
    fn verify_operator_signature_rejects_wrong_game_idx() {
        let (tx, prevouts, operator_kp, n_of_n_kp) = signed_contest_fixture();

        verify_operator_signature(
            &tx,
            &prevouts,
            &xonly(&operator_kp).into(),
            NonZero::new(GAME_IDX + 1).unwrap(),
            &xonly(&n_of_n_kp).into(),
            relative::Height::from_height(PROOF_TIMELOCK),
        );
    }

    #[test]
    #[should_panic(expected = "prevouts[0] is not the ContestProofConnector output")]
    fn verify_operator_signature_rejects_wrong_n_of_n_pubkey() {
        let (tx, prevouts, operator_kp, _n_of_n_kp) = signed_contest_fixture();
        let other = deterministic_keypair(9);

        verify_operator_signature(
            &tx,
            &prevouts,
            &xonly(&operator_kp).into(),
            NonZero::new(GAME_IDX).unwrap(),
            &xonly(&other).into(),
            relative::Height::from_height(PROOF_TIMELOCK),
        );
    }

    #[test]
    #[should_panic(expected = "prevouts[0] is not the ContestProofConnector output")]
    fn verify_operator_signature_rejects_wrong_proof_timelock() {
        let (tx, prevouts, operator_kp, n_of_n_kp) = signed_contest_fixture();

        verify_operator_signature(
            &tx,
            &prevouts,
            &xonly(&operator_kp).into(),
            NonZero::new(GAME_IDX).unwrap(),
            &xonly(&n_of_n_kp).into(),
            relative::Height::from_height(PROOF_TIMELOCK + 1),
        );
    }

    #[test]
    #[should_panic(expected = "operator signature should verify")]
    fn verify_operator_signature_rejects_tampered_tx() {
        let (mut tx, prevouts, operator_kp, n_of_n_kp) = signed_contest_fixture();
        // Mutate a sighash-covered field after signing; the schnorr verification
        // sees a sighash the operator never signed.
        tx.lock_time = absolute::LockTime::from_consensus(1);

        verify_operator_signature(
            &tx,
            &prevouts,
            &xonly(&operator_kp).into(),
            NonZero::new(GAME_IDX).unwrap(),
            &xonly(&n_of_n_kp).into(),
            relative::Height::from_height(PROOF_TIMELOCK),
        );
    }

    #[test]
    #[should_panic(expected = "first input should carry a key-path witness")]
    fn verify_operator_signature_rejects_empty_witness() {
        let (mut tx, prevouts, operator_kp, n_of_n_kp) = signed_contest_fixture();
        tx.input[0].witness = Witness::new();

        verify_operator_signature(
            &tx,
            &prevouts,
            &xonly(&operator_kp).into(),
            NonZero::new(GAME_IDX).unwrap(),
            &xonly(&n_of_n_kp).into(),
            relative::Height::from_height(PROOF_TIMELOCK),
        );
    }

    #[test]
    #[should_panic(expected = "witness should be a taproot key-spend signature")]
    fn verify_operator_signature_rejects_malformed_witness() {
        let (mut tx, prevouts, operator_kp, n_of_n_kp) = signed_contest_fixture();
        tx.input[0].witness = Witness::from_slice(&[vec![0u8; 32]]);

        verify_operator_signature(
            &tx,
            &prevouts,
            &xonly(&operator_kp).into(),
            NonZero::new(GAME_IDX).unwrap(),
            &xonly(&n_of_n_kp).into(),
            relative::Height::from_height(PROOF_TIMELOCK),
        );
    }

    #[test]
    fn process_counterproof_inner_commits_on_invalid_proof() {
        let input = canonical_counterproof_input();
        let output = run_counterproof(input.clone(), PredicateKey::never_accept());

        assert_eq!(output.game_idx, input.game_idx);
        assert_eq!(output.operator_pubkey, input.operator_pubkey);
    }

    #[test]
    fn process_counterproof_inner_commits_on_non_canonical_shape() {
        // Off-shape tx with a valid signature. `always_accept` would panic if the
        // embedded-proof check ran; reaching commit proves the short-circuit fired.
        let operator_kp = deterministic_keypair(1);
        let n_of_n_kp = deterministic_keypair(2);
        let game_idx = NonZero::new(GAME_IDX).unwrap();
        let connector = contest_connector(
            xonly(&operator_kp),
            xonly(&n_of_n_kp),
            game_idx,
            relative::Height::from_height(PROOF_TIMELOCK),
        );

        let (mut tx, prevouts) = unsigned_contest_tx(&connector);
        tx.output = vec![txout(ScriptBuf::new())];
        sign_input_zero(&mut tx, &prevouts, &operator_kp, &connector, game_idx);

        let output = run_counterproof(
            counterproof_input_from(tx, prevouts, &operator_kp, &n_of_n_kp),
            PredicateKey::always_accept(),
        );

        assert_eq!(output.game_idx, GAME_IDX);
    }

    #[test]
    #[should_panic(expected = "prevouts must match inputs 1:1")]
    fn process_counterproof_inner_rejects_prevouts_input_mismatch() {
        let mut input = canonical_counterproof_input();
        input
            .bridge_proof_tx_prevouts
            .push(BitcoinTxOut::from(txout(ScriptBuf::new())));
        run_counterproof(input, PredicateKey::never_accept());
    }

    #[test]
    #[should_panic(expected = "bridge_proof_tx must consensus-decode into a Transaction")]
    fn process_counterproof_inner_rejects_non_decodable_tx() {
        let mut input = canonical_counterproof_input();
        input.bridge_proof_tx = RawBitcoinTx::from_raw_bytes(vec![0xffu8; 4]);
        run_counterproof(input, PredicateKey::never_accept());
    }

    #[test]
    #[should_panic(expected = "game_idx must be non-zero")]
    fn process_counterproof_inner_rejects_zero_game_idx() {
        let mut input = canonical_counterproof_input();
        input.game_idx = 0;
        run_counterproof(input, PredicateKey::never_accept());
    }
}
