//! Bridge counterproof statements.

use std::num::NonZero;

use bitcoin::{
    Amount, Network, Script, Transaction, TxOut, opcodes, relative,
    script::Instruction,
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot,
};
use secp256k1::{Message, SECP256K1};
use strata_bridge_connectors::prelude::ContestProofConnector;
use strata_btc_types::BitcoinXOnlyPublicKey;
use zkaleido::{ProofReceipt, ZkVmEnv, ZkVmEnvSsz};

#[cfg(not(target_os = "zkvm"))]
use crate::genesis::load_genesis_from_env;
use crate::types::{BridgeCounterproofGenesis, CounterproofInput, CounterproofOutput};

/// Native entry point: loads genesis and runs the counterproof.
#[cfg(not(target_os = "zkvm"))]
pub fn process_counterproof(zkvm: &impl ZkVmEnv) {
    let genesis = load_genesis_from_env();
    process_counterproof_inner(zkvm, &genesis);
}

/// zkVM entry point: runs the counterproof.
#[cfg(target_os = "zkvm")]
pub fn process_counterproof(zkvm: &impl ZkVmEnv, genesis: BridgeCounterproofGenesis) {
    process_counterproof_inner(zkvm, &genesis);
}

/// Reads the SSZ input, verifies the counterproof, and commits the output.
fn process_counterproof_inner(zkvm: &impl ZkVmEnv, genesis: &BridgeCounterproofGenesis) {
    let CounterproofInput {
        game_idx,
        operator_pubkey,
        n_of_n_pubkey,
        proof_timelock,
        bridge_proof_tx,
        bridge_proof_tx_prevouts,
        bridge_proof_tx_input_idx,
    } = zkvm.read_ssz();
    let tx: Transaction = (&bridge_proof_tx)
        .try_into()
        .expect("invalid counterproof: invalid encoding of bridge proof transaction");
    let prevouts: Vec<TxOut> = bridge_proof_tx_prevouts
        .into_iter()
        .map(TxOut::from)
        .collect();
    assert_eq!(
        tx.input.len(),
        prevouts.len(),
        "invalid counterproof: length of prevouts not equal number of transaction inputs",
    );

    let game_idx_nz =
        NonZero::new(game_idx).expect("invalid counterproof: game index cannot be zero");
    verify_operator_signature(
        &tx,
        &prevouts,
        bridge_proof_tx_input_idx,
        &operator_pubkey,
        game_idx_nz,
        &n_of_n_pubkey,
        relative::Height::from_height(proof_timelock),
    );

    if let Some(bridge_proof_receipt) = extract_bridge_proof(&tx, bridge_proof_tx_input_idx) {
        assert!(
            genesis
                .bridge_proof_vk
                .verify_claim_witness(
                    bridge_proof_receipt.public_values().as_bytes(),
                    bridge_proof_receipt.proof().as_bytes(),
                )
                .is_err(),
            "invalid counterproof: bridge proof is valid",
        );
    }

    zkvm.commit_ssz(&CounterproofOutput {
        operator_pubkey,
        game_idx,
    });
}

/// Asserts that the contest-proof txin has a valid operator signature.
///
/// The contest-proof txin is indexed by `txin_idx`.
///
/// # Counterproof success scenarios
///
/// If this function returns, then the counterproof validation continues.
///
/// # Counterproof failure scenarios
///
/// This function panics if the contest-proof txin has malformed witness data
/// or if the operator signature fails to verify. In this case, the counterproof
/// is immediately invalid.
fn verify_operator_signature(
    tx: &Transaction,
    prevouts: &[TxOut],
    txin_idx: u32,
    operator_pubkey: &BitcoinXOnlyPublicKey,
    game_idx: NonZero<u32>,
    n_of_n_pubkey: &BitcoinXOnlyPublicKey,
    proof_timelock: relative::Height,
) {
    let txin_idx = txin_idx as usize;
    let wit_elem = tx.input[txin_idx]
        .witness
        .iter()
        .next()
        .expect("invalid counterproof: contest-proof txin has no witness");
    let tap_sig = taproot::Signature::from_slice(wit_elem)
        .expect("invalid counterproof: contest-proof txin has no signature");

    let mut cache = SighashCache::new(tx);
    let msg = cache
        .taproot_key_spend_signature_hash(txin_idx, &Prevouts::All(prevouts), tap_sig.sighash_type)
        .map(Message::from)
        .expect("sighash computation should never fail");

    let output_key = ContestProofConnector::new(
        Network::Bitcoin,
        n_of_n_pubkey.to_xonly_public_key(),
        operator_pubkey.to_xonly_public_key(),
        game_idx,
        proof_timelock,
        Amount::ZERO,
    )
    .output_key();

    SECP256K1
        .verify_schnorr(&tap_sig.signature, &msg, &output_key.to_x_only_public_key())
        .expect("invalid counterproof: contest-proof txin signature verification failed");
}

/// Extracts the bridge proof from the given `bridge_proof_tx`.
///
/// # Warning
///
/// This function must be called after [`verify_operator_signature()`],
/// to ensure that the bridge proof transaction has a valid operator signature.
///
/// # Counterproof success scenarios
///
/// This function returns `None` if the bridge proof transaction has the wrong
/// format. In this case, the counterproof is immediately valid.
///
/// If this function returns `Some`, then the counterproof validation continues.
///
/// # Counterproof failure scenarios
///
/// This function panics if the bridge proof transaction doesn't have a signature
/// at the given input. This is impossible after calling [`verify_operator_signature()`].
fn extract_bridge_proof(bridge_proof_tx: &Transaction, txin_idx: u32) -> Option<ProofReceipt> {
    let wit_elem = bridge_proof_tx.input[txin_idx as usize]
        .witness
        .iter()
        .next()
        .expect("operator signature has already been verified");
    let tap_sig = taproot::Signature::from_slice(wit_elem)
        .expect("operator signature has already been verified");

    // Return `None` if the bridge proof transaction has the wrong format.
    if tap_sig.sighash_type != TapSighashType::Default {
        return None;
    }
    let first_out = bridge_proof_tx.output.first()?;
    let data = extract_op_return_payload(&first_out.script_pubkey)?;

    // Return the decoded bridge proof.
    borsh::from_slice::<ProofReceipt>(data).ok()
}

/// Extracts the pushed payload of an `OP_RETURN <PushBytes>` script.
///
/// # Counterproof success scenarios
///
/// This function returns `None` if the script has the wrong format.
/// In this case, the counterproof is immediately valid.
fn extract_op_return_payload(script_pubkey: &Script) -> Option<&[u8]> {
    let mut it = script_pubkey.instructions();
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
        Amount, Network, ScriptBuf, TxIn, Witness, absolute,
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
    const TXIN_IDX: u32 = 0;

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
            bridge_proof_tx_prevouts: prevouts
                .into_iter()
                .map(|p| BitcoinTxOut::try_from(p).expect("fixture prevout fits SSZ bounds"))
                .collect(),
            bridge_proof_tx_input_idx: TXIN_IDX,
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
    fn extract_bridge_proof_malformed() {
        let mut non_default_sighash_tx = proof_receipt_tx();
        let mut signature = vec![1u8; 64];
        signature.push(TapSighashType::All as u8);
        non_default_sighash_tx.input[0].witness = Witness::from_slice(&[signature]);

        let mut no_output = proof_receipt_tx();
        no_output.output = vec![];

        let mut output_script_empty = proof_receipt_tx();
        output_script_empty.output[0].script_pubkey = ScriptBuf::new();

        let mut output_script_too_many_elements = proof_receipt_tx();
        output_script_too_many_elements.output[0].script_pubkey = op_return_script(vec![1u8, 2, 3]);

        let cases = [
            non_default_sighash_tx,
            no_output,
            output_script_empty,
            output_script_too_many_elements,
        ];
        for tx in cases {
            assert!(extract_bridge_proof(&tx, TXIN_IDX).is_none());
        }
    }

    #[test]
    fn extract_bridge_proof_correct_format() {
        assert!(extract_bridge_proof(&proof_receipt_tx(), TXIN_IDX).is_some());
    }

    #[test]
    fn verify_operator_signature_accepts_canonical_signed_tx() {
        let (tx, prevouts, operator_kp, n_of_n_kp) = signed_contest_fixture();

        verify_operator_signature(
            &tx,
            &prevouts,
            TXIN_IDX,
            &xonly(&operator_kp).into(),
            NonZero::new(GAME_IDX).unwrap(),
            &xonly(&n_of_n_kp).into(),
            relative::Height::from_height(PROOF_TIMELOCK),
        );
    }

    #[test]
    #[should_panic(
        expected = "invalid counterproof: contest-proof txin signature verification failed"
    )]
    fn verify_operator_signature_rejects_wrong_operator_pubkey() {
        let (tx, prevouts, _operator_kp, n_of_n_kp) = signed_contest_fixture();
        let other = deterministic_keypair(9);

        verify_operator_signature(
            &tx,
            &prevouts,
            TXIN_IDX,
            &xonly(&other).into(),
            NonZero::new(GAME_IDX).unwrap(),
            &xonly(&n_of_n_kp).into(),
            relative::Height::from_height(PROOF_TIMELOCK),
        );
    }

    #[test]
    #[should_panic(
        expected = "invalid counterproof: contest-proof txin signature verification failed"
    )]
    fn verify_operator_signature_rejects_wrong_game_idx() {
        let (tx, prevouts, operator_kp, n_of_n_kp) = signed_contest_fixture();

        verify_operator_signature(
            &tx,
            &prevouts,
            TXIN_IDX,
            &xonly(&operator_kp).into(),
            NonZero::new(GAME_IDX + 1).unwrap(),
            &xonly(&n_of_n_kp).into(),
            relative::Height::from_height(PROOF_TIMELOCK),
        );
    }

    #[test]
    #[should_panic(
        expected = "invalid counterproof: contest-proof txin signature verification failed"
    )]
    fn verify_operator_signature_rejects_wrong_n_of_n_pubkey() {
        let (tx, prevouts, operator_kp, _n_of_n_kp) = signed_contest_fixture();
        let other = deterministic_keypair(9);

        verify_operator_signature(
            &tx,
            &prevouts,
            TXIN_IDX,
            &xonly(&operator_kp).into(),
            NonZero::new(GAME_IDX).unwrap(),
            &xonly(&other).into(),
            relative::Height::from_height(PROOF_TIMELOCK),
        );
    }

    #[test]
    #[should_panic(
        expected = "invalid counterproof: contest-proof txin signature verification failed"
    )]
    fn verify_operator_signature_rejects_wrong_proof_timelock() {
        let (tx, prevouts, operator_kp, n_of_n_kp) = signed_contest_fixture();

        verify_operator_signature(
            &tx,
            &prevouts,
            TXIN_IDX,
            &xonly(&operator_kp).into(),
            NonZero::new(GAME_IDX).unwrap(),
            &xonly(&n_of_n_kp).into(),
            relative::Height::from_height(PROOF_TIMELOCK + 1),
        );
    }

    #[test]
    #[should_panic(
        expected = "invalid counterproof: contest-proof txin signature verification failed"
    )]
    fn verify_operator_signature_rejects_tampered_tx() {
        let (mut tx, prevouts, operator_kp, n_of_n_kp) = signed_contest_fixture();
        // Mutate a sighash-covered field after signing; the schnorr verification
        // sees a sighash the operator never signed.
        tx.lock_time = absolute::LockTime::from_consensus(1);

        verify_operator_signature(
            &tx,
            &prevouts,
            TXIN_IDX,
            &xonly(&operator_kp).into(),
            NonZero::new(GAME_IDX).unwrap(),
            &xonly(&n_of_n_kp).into(),
            relative::Height::from_height(PROOF_TIMELOCK),
        );
    }

    #[test]
    #[should_panic(expected = "invalid counterproof: contest-proof txin has no witness")]
    fn verify_operator_signature_rejects_empty_witness() {
        let (mut tx, prevouts, operator_kp, n_of_n_kp) = signed_contest_fixture();
        tx.input[0].witness = Witness::new();

        verify_operator_signature(
            &tx,
            &prevouts,
            TXIN_IDX,
            &xonly(&operator_kp).into(),
            NonZero::new(GAME_IDX).unwrap(),
            &xonly(&n_of_n_kp).into(),
            relative::Height::from_height(PROOF_TIMELOCK),
        );
    }

    #[test]
    #[should_panic(expected = "invalid counterproof: contest-proof txin has no signature")]
    fn verify_operator_signature_rejects_malformed_witness() {
        let (mut tx, prevouts, operator_kp, n_of_n_kp) = signed_contest_fixture();
        tx.input[0].witness = Witness::from_slice(&[vec![0u8; 32]]);

        verify_operator_signature(
            &tx,
            &prevouts,
            TXIN_IDX,
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
    #[should_panic(expected = "invalid counterproof: bridge proof is valid")]
    fn process_counterproof_inner_rejects_valid_proof() {
        let input = canonical_counterproof_input();
        run_counterproof(input, PredicateKey::always_accept());
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
    #[should_panic(
        expected = "invalid counterproof: length of prevouts not equal number of transaction inputs"
    )]
    fn process_counterproof_inner_rejects_prevouts_input_mismatch() {
        let mut input = canonical_counterproof_input();
        input.bridge_proof_tx_prevouts.push(
            BitcoinTxOut::try_from(txout(ScriptBuf::new())).expect("empty script fits bounds"),
        );
        run_counterproof(input, PredicateKey::never_accept());
    }

    #[test]
    #[should_panic(expected = "invalid counterproof: invalid encoding of bridge proof transaction")]
    fn process_counterproof_inner_rejects_non_decodable_tx() {
        let mut input = canonical_counterproof_input();
        input.bridge_proof_tx = RawBitcoinTx::from_raw_bytes(vec![0xffu8; 4]);
        run_counterproof(input, PredicateKey::never_accept());
    }

    #[test]
    #[should_panic(expected = "invalid counterproof: game index cannot be zero")]
    fn process_counterproof_inner_rejects_zero_game_idx() {
        let mut input = canonical_counterproof_input();
        input.game_idx = 0;
        run_counterproof(input, PredicateKey::never_accept());
    }
}
