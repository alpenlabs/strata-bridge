//! Bridge counterproof statements.

use std::num::NonZero;

use bitcoin::{
    Amount, Network, Script, Transaction, TxOut, opcodes, relative,
    script::Instruction,
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot,
};
use secp256k1::{Message, SECP256K1};
use ssz::Decode;
use strata_asm_proto_bridge_v1::OperatorClaimUnlock;
use strata_asm_proto_bridge_v1_txs::BRIDGE_V1_SUBPROTOCOL_ID;
use strata_bridge_connectors::prelude::ContestProofConnector;
use strata_bridge_proof::BridgeProofOutput;
use strata_bridge_proof_common::{verify_claim_unlock_inclusion, verify_moho_proof};
use strata_btc_types::BitcoinXOnlyPublicKey;
use strata_codec::decode_buf_exact;
use zkaleido::{ProofReceipt, ZkVmEnv, ZkVmEnvSsz};

use crate::{
    CounterproofMode, HeavierChainProof,
    genesis::{BridgeCounterproofGenesis, load_genesis},
    types::{CounterproofInput, CounterproofOutput},
};

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
        mode,
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
    let bridge_proof_receipt = extract_bridge_proof(&tx, bridge_proof_tx_input_idx);

    match mode {
        CounterproofMode::InvalidBridgeProof => 'invalid_bridge_proof: {
            let Some(bridge_proof_receipt) = bridge_proof_receipt.as_ref() else {
                break 'invalid_bridge_proof;
            };

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
        CounterproofMode::HeavierChain(heavier_chain_proof) => 'heavier_chain: {
            let Some(bridge_proof_receipt) = bridge_proof_receipt.as_ref() else {
                break 'heavier_chain;
            };

            let HeavierChainProof {
                moho_state: heavier_moho_state,
                moho_proof: heavier_moho_proof,
                claim_unlock: heavier_claim_unlock,
                claim_unlock_inclusion_proof: heavier_inclusion_proof,
            } = heavier_chain_proof;

            let heavier_claim_unlock =
                decode_buf_exact::<OperatorClaimUnlock>(&heavier_claim_unlock)
                    .expect("invalid heavier chain: invalid claim unlock encoding");

            let (total_pow, bridge_proof_claim_unlock, mmr_idx) = BridgeProofOutput::from_ssz_bytes(bridge_proof_receipt.public_values().as_bytes())
                .ok()
                .and_then(|output| {
                    decode_buf_exact::<OperatorClaimUnlock>(&output.claim_unlock)
                        .ok()
                        .map(|claim_unlock| (output.total_pow, claim_unlock, output.mmr_idx))
                })
                .expect("if public values of bridge proof are invalid, then the bridge proof is invalid (use CounterproofMode::InvalidBridgeProof)");

            // Fail if `heavier_moho_proof` is invalid.
            verify_moho_proof(
                &heavier_moho_state,
                &heavier_moho_proof,
                genesis.genesis_moho_state.reference(),
                genesis.moho_vk.clone(),
            );

            let heavier_bridge_container = heavier_moho_state
                .export_state()
                .containers()
                .iter()
                .find(|c| c.container_id() == BRIDGE_V1_SUBPROTOCOL_ID)
                .expect("moho_state must contain a bridge-v1 export container");

            // Fail if the heavier chain doesn't have more proof of work than the operator chain.
            if heavier_bridge_container.extra_data() <= &total_pow {
                panic!("invalid heavier chain: not enough proof of work");
            }

            // Immediately succeed if `mmr_idx` is out of bounds
            // for `heavier_moho_state`.
            //
            // This means that the heavier chain has fewer claim unlocks
            // than the operator chain, which means that there are fake
            // claim unlocks on the operator chain.
            //
            // In this case, `heavier_claim_unlock` is unrestricted,
            // because membership in the heavier chain is not checked.
            // For example, if the heavier chain has no claim unlocks,
            // then we can use a dummy value.
            if heavier_bridge_container.entries_mmr().num_entries() <= mmr_idx {
                break 'heavier_chain;
            }

            // Fail if `heavier_claim_unlock` is not at index `mmr_idx`.
            if heavier_inclusion_proof.index != mmr_idx {
                panic!("invalid heavier chain: claim unlock index must match bridge proof")
            }

            // Fail if `heavier_claim_unlock` is not included in `heavier_moho_state`.
            //
            // This has to be done after `mmr_idx` is checked for bounds.
            // If `mmr_idx` is out of bounds, then ANY `heavier_inclusion_proof` is accepted.
            verify_claim_unlock_inclusion(
                &heavier_claim_unlock,
                heavier_bridge_container,
                &heavier_inclusion_proof,
            );

            // Fail if `heavier_claim_unlock` is equal to `bridge_proof_claim_unlock`.
            //
            // If the heavier chain is an extension of the operator chain,
            // i.e. the watchtower just waited a few blocks after the operator
            // posted the bridge proof, then this equality is triggered.
            if heavier_claim_unlock == bridge_proof_claim_unlock {
                panic!("invalid heavier chain: claim unlock must be different from bridge proof")
            }
        }
    }

    zkvm.commit_ssz(&CounterproofOutput {
        game_idx,
        operator_pubkey,
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
    use std::sync::LazyLock;

    use bitcoin::{
        Amount, Network, ScriptBuf, Txid, Witness, absolute,
        hashes::Hash,
        opcodes::all::{OP_PUSHNUM_1, OP_RETURN},
        script::{Builder, PushBytesBuf},
    };
    use secp256k1::{Keypair, XOnlyPublicKey};
    use ssz::{Decode, Encode};
    use strata_bridge_connectors::Connector;
    use strata_bridge_proof_common::{MOHO_GENESIS_ATTESTATION, generate_moho_state};
    use strata_bridge_test_utils::bitcoin::generate_keypair;
    use strata_bridge_tx_graph::transactions::prelude::{BridgeProofData, BridgeProofTx};
    use strata_codec::encode_to_vec;
    use strata_predicate::PredicateKey;
    use zkaleido::{Proof, PublicValues};
    use zkaleido_native_adapter::NativeMachine;

    use super::*;
    use crate::{BitcoinTxOut, CounterproofMode, RawBitcoinTx};

    const GAME_IDX: NonZero<u32> = NonZero::new(7).unwrap();
    const PROOF_TIMELOCK: relative::Height = relative::Height::from_height(100);
    const TXIN_IDX: u32 = 0;

    static OPERATOR_KEYPAIR: LazyLock<Keypair> = LazyLock::new(generate_keypair);
    static OPERATOR_PUBKEY: LazyLock<XOnlyPublicKey> =
        LazyLock::new(|| OPERATOR_KEYPAIR.x_only_public_key().0);
    static N_OF_N_PUBKEY: LazyLock<XOnlyPublicKey> =
        LazyLock::new(|| generate_keypair().x_only_public_key().0);

    static CONTEST_PROOF_CONNECTOR: LazyLock<ContestProofConnector> = LazyLock::new(|| {
        ContestProofConnector::new(
            Network::Regtest,
            *N_OF_N_PUBKEY,
            *OPERATOR_PUBKEY,
            GAME_IDX,
            PROOF_TIMELOCK,
            Amount::ZERO,
        )
    });
    static PREVOUTS: LazyLock<[TxOut; 1]> = LazyLock::new(|| [CONTEST_PROOF_CONNECTOR.tx_out()]);
    static BRIDGE_PROOF_CLAIM_UNLOCK: LazyLock<OperatorClaimUnlock> =
        LazyLock::new(|| OperatorClaimUnlock::new(0, 0));
    static HEAVIER_CHAIN_CLAIM_UNLOCK: LazyLock<OperatorClaimUnlock> =
        LazyLock::new(|| OperatorClaimUnlock::new(0, 1));
    const BRIDGE_PROOF_POW: [u8; 32] = [1; 32];
    const HEAVIER_CHAIN_POW: [u8; 32] = [2; 32];
    static BRIDGE_PROOF_TX_UNSIGNED: LazyLock<BridgeProofTx> = LazyLock::new(|| {
        let bridge_proof_output = BridgeProofOutput {
            total_pow: BRIDGE_PROOF_POW,
            claim_unlock: encode_to_vec::<OperatorClaimUnlock>(&BRIDGE_PROOF_CLAIM_UNLOCK).unwrap(),
            mmr_idx: 0,
        };
        let receipt = ProofReceipt::new(
            Proof::new(vec![]),
            PublicValues::new(bridge_proof_output.as_ssz_bytes()),
        );
        let proof_bytes = borsh::to_vec(&receipt).unwrap();
        let data = BridgeProofData {
            contest_txid: Txid::all_zeros(),
            proof_bytes,
            game_index: GAME_IDX,
        };

        BridgeProofTx::new(data, *CONTEST_PROOF_CONNECTOR)
    });
    static BRIDGE_PROOF_TX: LazyLock<Transaction> = LazyLock::new(|| {
        let tx = BRIDGE_PROOF_TX_UNSIGNED.clone();
        let signing_info = tx.signing_info_partial();
        let tweaked_operator_key = OPERATOR_KEYPAIR
            .add_xonly_tweak(
                SECP256K1,
                &ContestProofConnector::operator_key_tweak(GAME_IDX),
            )
            .expect("game-idx tweak is valid");

        tx.finalize_partial(signing_info.sign(&tweaked_operator_key))
    });
    static BRIDGE_PROOF_TX_SIGNED_BUT_INVALID_FORMAT: LazyLock<Transaction> = LazyLock::new(|| {
        let mut tx = BRIDGE_PROOF_TX_UNSIGNED.clone();
        tx.as_mut().output[0].script_pubkey = ScriptBuf::new();
        let signing_info = tx.signing_info_partial();
        let tweaked_operator_key = OPERATOR_KEYPAIR
            .add_xonly_tweak(
                SECP256K1,
                &ContestProofConnector::operator_key_tweak(GAME_IDX),
            )
            .expect("game-idx tweak is valid");

        tx.finalize_partial(signing_info.sign(&tweaked_operator_key))
    });
    static BRIDGE_PROOF_TX_SIGNED_BUT_INVALID_PROOF: LazyLock<Transaction> = LazyLock::new(|| {
        let receipt = ProofReceipt::new(Proof::new(vec![]), PublicValues::new(vec![]));
        let data = BridgeProofData {
            contest_txid: Txid::all_zeros(),
            proof_bytes: borsh::to_vec(&receipt).unwrap(),
            game_index: GAME_IDX,
        };
        let tx = BridgeProofTx::new(data, *CONTEST_PROOF_CONNECTOR);
        let signing_info = tx.signing_info_partial();
        let tweaked_operator_key = OPERATOR_KEYPAIR
            .add_xonly_tweak(
                SECP256K1,
                &ContestProofConnector::operator_key_tweak(GAME_IDX),
            )
            .expect("game-idx tweak is valid");

        tx.finalize_partial(signing_info.sign(&tweaked_operator_key))
    });

    fn op_return_script(data: Vec<u8>) -> ScriptBuf {
        let payload = PushBytesBuf::try_from(data).unwrap();
        ScriptBuf::new_op_return(payload)
    }

    #[derive(Debug, Clone)]
    struct RuntimeArgs {
        pub input: CounterproofInput,
        pub bridge_proof_vk: PredicateKey,
        pub moho_vk: PredicateKey,
    }

    /// Drives `process_counterproof_inner` through a `NativeMachine`.
    fn run_counterproof(args: RuntimeArgs) -> CounterproofOutput {
        let mut machine = NativeMachine::new();
        machine.write_slice(args.input.as_ssz_bytes());

        let genesis = BridgeCounterproofGenesis {
            bridge_proof_vk: args.bridge_proof_vk,
            moho_vk: args.moho_vk,
            genesis_moho_state: *MOHO_GENESIS_ATTESTATION,
        };

        process_counterproof_inner(&machine, &genesis);
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
        let mut non_default_sighash_tx = BRIDGE_PROOF_TX.clone();

        let mut signature = vec![1u8; 64];
        signature.push(TapSighashType::All as u8);
        non_default_sighash_tx.input[0].witness = Witness::from_slice(&[signature]);

        let mut no_output = BRIDGE_PROOF_TX.clone();
        no_output.output = vec![];

        let mut output_script_empty = BRIDGE_PROOF_TX.clone();
        output_script_empty.output[0].script_pubkey = ScriptBuf::new();

        let mut output_script_too_many_elements = BRIDGE_PROOF_TX.clone();
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
        assert!(extract_bridge_proof(&BRIDGE_PROOF_TX, TXIN_IDX).is_some());
    }

    #[test]
    fn verify_operator_signature_accepts_canonical_signed_tx() {
        verify_operator_signature(
            &BRIDGE_PROOF_TX,
            PREVOUTS.as_ref(),
            TXIN_IDX,
            &(*OPERATOR_PUBKEY).into(),
            GAME_IDX,
            &(*N_OF_N_PUBKEY).into(),
            PROOF_TIMELOCK,
        );
    }

    #[test]
    #[should_panic(
        expected = "invalid counterproof: contest-proof txin signature verification failed"
    )]
    fn verify_operator_signature_rejects_wrong_operator_pubkey() {
        let not_operator_pubkey = loop {
            let pubkey = generate_keypair().x_only_public_key().0;
            if pubkey != *OPERATOR_PUBKEY {
                break pubkey;
            }
        };

        verify_operator_signature(
            &BRIDGE_PROOF_TX,
            PREVOUTS.as_ref(),
            TXIN_IDX,
            &not_operator_pubkey.into(),
            GAME_IDX,
            &(*N_OF_N_PUBKEY).into(),
            PROOF_TIMELOCK,
        );
    }

    #[test]
    #[should_panic(
        expected = "invalid counterproof: contest-proof txin signature verification failed"
    )]
    fn verify_operator_signature_rejects_wrong_game_idx() {
        let not_game_index = GAME_IDX.saturating_add(1);

        verify_operator_signature(
            &BRIDGE_PROOF_TX,
            PREVOUTS.as_ref(),
            TXIN_IDX,
            &(*OPERATOR_PUBKEY).into(),
            not_game_index,
            &(*N_OF_N_PUBKEY).into(),
            PROOF_TIMELOCK,
        );
    }

    #[test]
    #[should_panic(
        expected = "invalid counterproof: contest-proof txin signature verification failed"
    )]
    fn verify_operator_signature_rejects_wrong_n_of_n_pubkey() {
        let not_n_of_n_pubkey = loop {
            let pubkey = generate_keypair().x_only_public_key().0;
            if pubkey != *N_OF_N_PUBKEY {
                break pubkey;
            }
        };

        verify_operator_signature(
            &BRIDGE_PROOF_TX,
            PREVOUTS.as_ref(),
            TXIN_IDX,
            &(*OPERATOR_PUBKEY).into(),
            GAME_IDX,
            &not_n_of_n_pubkey.into(),
            PROOF_TIMELOCK,
        );
    }

    #[test]
    #[should_panic(
        expected = "invalid counterproof: contest-proof txin signature verification failed"
    )]
    fn verify_operator_signature_rejects_wrong_proof_timelock() {
        let not_proof_timelock = relative::Height::from(PROOF_TIMELOCK.value() + 1);

        verify_operator_signature(
            &BRIDGE_PROOF_TX,
            PREVOUTS.as_ref(),
            TXIN_IDX,
            &(*OPERATOR_PUBKEY).into(),
            GAME_IDX,
            &(*N_OF_N_PUBKEY).into(),
            not_proof_timelock,
        );
    }

    #[test]
    #[should_panic(
        expected = "invalid counterproof: contest-proof txin signature verification failed"
    )]
    fn verify_operator_signature_rejects_tampered_tx() {
        let mut tx = BRIDGE_PROOF_TX.clone();
        // Mutate a sighash-covered field after signing; the schnorr verification
        // sees a sighash the operator never signed.
        tx.lock_time = absolute::LockTime::from_consensus(1);

        verify_operator_signature(
            &tx,
            PREVOUTS.as_ref(),
            TXIN_IDX,
            &(*OPERATOR_PUBKEY).into(),
            GAME_IDX,
            &(*N_OF_N_PUBKEY).into(),
            PROOF_TIMELOCK,
        );
    }

    #[test]
    #[should_panic(expected = "invalid counterproof: contest-proof txin has no witness")]
    fn verify_operator_signature_rejects_empty_witness() {
        let mut tx = BRIDGE_PROOF_TX.clone();
        tx.input[0].witness = Witness::new();

        verify_operator_signature(
            &tx,
            PREVOUTS.as_ref(),
            TXIN_IDX,
            &(*OPERATOR_PUBKEY).into(),
            GAME_IDX,
            &(*N_OF_N_PUBKEY).into(),
            PROOF_TIMELOCK,
        );
    }

    #[test]
    #[should_panic(expected = "invalid counterproof: contest-proof txin has no signature")]
    fn verify_operator_signature_rejects_malformed_witness() {
        let mut tx = BRIDGE_PROOF_TX.clone();
        tx.input[0].witness = Witness::from_slice(&[vec![0u8; 32]]);

        verify_operator_signature(
            &tx,
            PREVOUTS.as_ref(),
            TXIN_IDX,
            &(*OPERATOR_PUBKEY).into(),
            GAME_IDX,
            &(*N_OF_N_PUBKEY).into(),
            PROOF_TIMELOCK,
        );
    }

    static INPUT_FOR_INVALID_BRIDGE_PROOF: LazyLock<CounterproofInput> =
        LazyLock::new(|| CounterproofInput {
            game_idx: GAME_IDX.get(),
            operator_pubkey: (*OPERATOR_PUBKEY).into(),
            n_of_n_pubkey: (*N_OF_N_PUBKEY).into(),
            proof_timelock: PROOF_TIMELOCK.value(),
            bridge_proof_tx: BRIDGE_PROOF_TX.clone().into(),
            bridge_proof_tx_prevouts: PREVOUTS.iter().cloned().map(BitcoinTxOut::from).collect(),
            bridge_proof_tx_input_idx: TXIN_IDX,
            mode: CounterproofMode::InvalidBridgeProof,
        });

    /// Unit tests for input sanitization that happens
    /// before the logic of the given `CounterproofMode` is executed.
    mod input_sanitization {
        use super::*;

        #[test]
        #[should_panic(
            expected = "invalid counterproof: invalid encoding of bridge proof transaction"
        )]
        fn counterproof_invalid_if_bridge_proof_tx_invalid_encoding() {
            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.bridge_proof_tx = RawBitcoinTx::from_raw_bytes(vec![0xffu8; 4]);

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::never_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        #[should_panic(
            expected = "invalid counterproof: length of prevouts not equal number of transaction inputs"
        )]
        fn counterproof_invalid_if_prevouts_invalid_length() {
            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input
                .bridge_proof_tx_prevouts
                .push(BitcoinTxOut::from(TxOut::NULL));

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::never_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        #[should_panic(expected = "invalid counterproof: game index cannot be zero")]
        fn counterproof_invalid_if_game_index_zero() {
            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.game_idx = 0;

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::never_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }
    }

    /// Unit tests for [`CounterproofMode::InvalidBridgeProof`].
    mod invalid_bridge_proof {
        use super::*;

        #[test]
        fn counterproof_valid_if_bridge_proof_tx_malformed() {
            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.bridge_proof_tx =
                RawBitcoinTx::from(BRIDGE_PROOF_TX_SIGNED_BUT_INVALID_FORMAT.clone());

            let output = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
            assert_eq!(output.game_idx, GAME_IDX.get());
        }

        #[test]
        #[should_panic(expected = "invalid counterproof: bridge proof is valid")]
        fn counterproof_invalid_if_bridge_proof_valid() {
            let input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();

            let _ = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        fn counterproof_valid_if_bridge_proof_invalid() {
            let input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();

            let output = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::never_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
            assert_eq!(output.game_idx, GAME_IDX.get());
            assert_eq!(output.operator_pubkey, (*OPERATOR_PUBKEY).into());
        }
    }

    static INPUT_FOR_HEAVIER_CHAIN: LazyLock<CounterproofInput> = LazyLock::new(|| {
        let (heavier_moho_state, heavier_moho_proof, [heavier_inclusion_proof]) =
            generate_moho_state([HEAVIER_CHAIN_CLAIM_UNLOCK.clone()], HEAVIER_CHAIN_POW);

        CounterproofInput {
            game_idx: GAME_IDX.get(),
            operator_pubkey: (*OPERATOR_PUBKEY).into(),
            n_of_n_pubkey: (*N_OF_N_PUBKEY).into(),
            proof_timelock: PROOF_TIMELOCK.value(),
            bridge_proof_tx: BRIDGE_PROOF_TX.clone().into(),
            bridge_proof_tx_prevouts: PREVOUTS.iter().cloned().map(BitcoinTxOut::from).collect(),
            bridge_proof_tx_input_idx: TXIN_IDX,
            mode: CounterproofMode::HeavierChain(HeavierChainProof::new(
                heavier_moho_state,
                heavier_moho_proof,
                HEAVIER_CHAIN_CLAIM_UNLOCK.clone(),
                heavier_inclusion_proof,
            )),
        }
    });

    /// Unit tests for [`CounterproofMode::HeavierChain`].
    mod heavier_chain {

        use strata_merkle::MerkleProofB32;

        use super::*;

        #[test]
        fn counterproof_valid_if_bridge_proof_tx_malformed() {
            let mut input = INPUT_FOR_HEAVIER_CHAIN.clone();
            input.bridge_proof_tx =
                RawBitcoinTx::from(BRIDGE_PROOF_TX_SIGNED_BUT_INVALID_FORMAT.clone());

            let output = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
            assert_eq!(output.game_idx, GAME_IDX.get());
        }

        #[test]
        #[should_panic(expected = "invalid heavier chain: invalid claim unlock encoding")]
        fn counterproof_invalid_if_heavier_claim_unlock_malformed() {
            let mut input = INPUT_FOR_HEAVIER_CHAIN.clone();
            if let CounterproofMode::HeavierChain(ref mut heavier_chain) = input.mode {
                heavier_chain.claim_unlock = vec![];
            }

            let _ = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        #[should_panic(
            expected = "if public values of bridge proof are invalid, then the bridge proof is invalid (use CounterproofMode::InvalidBridgeProof)"
        )]
        fn counterproof_invalid_if_bridge_proof_malformed() {
            let mut input = INPUT_FOR_HEAVIER_CHAIN.clone();
            input.bridge_proof_tx =
                RawBitcoinTx::from(BRIDGE_PROOF_TX_SIGNED_BUT_INVALID_PROOF.clone());

            let _ = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        #[should_panic(expected = "moho proof verification failed")]
        fn counterproof_invalid_if_heavier_moho_proof_invalid() {
            let input = INPUT_FOR_HEAVIER_CHAIN.clone();

            let _ = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::never_accept(),
            });
        }

        #[test]
        #[should_panic(expected = "invalid heavier chain: not enough proof of work")]
        fn counterproof_invalid_if_not_enough_pow() {
            let mut input = INPUT_FOR_HEAVIER_CHAIN.clone();
            let not_enough_pow = BRIDGE_PROOF_POW;
            let (heavier_moho_state, heavier_moho_proof, [heavier_inclusion_proof]) =
                generate_moho_state([HEAVIER_CHAIN_CLAIM_UNLOCK.clone()], not_enough_pow);
            input.mode = CounterproofMode::HeavierChain(HeavierChainProof::new(
                heavier_moho_state,
                heavier_moho_proof,
                HEAVIER_CHAIN_CLAIM_UNLOCK.clone(),
                heavier_inclusion_proof,
            ));

            let _ = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        fn counterproof_valid_if_mmr_out_of_bounds() {
            let mut input = INPUT_FOR_HEAVIER_CHAIN.clone();
            let (heavier_moho_state, heavier_moho_proof, []) =
                generate_moho_state([], HEAVIER_CHAIN_POW);
            input.mode = CounterproofMode::HeavierChain(HeavierChainProof::new(
                heavier_moho_state,
                heavier_moho_proof,
                HEAVIER_CHAIN_CLAIM_UNLOCK.clone(),
                // dummy inclusion proof: don't care
                MerkleProofB32::new_zero(),
            ));

            let output = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
            assert_eq!(output.game_idx, GAME_IDX.get());
            assert_eq!(output.operator_pubkey, (*OPERATOR_PUBKEY).into());
        }

        #[test]
        #[should_panic(
            expected = "invalid heavier chain: claim unlock index must match bridge proof"
        )]
        fn counterproof_invalid_if_mmr_different() {
            let mut input = INPUT_FOR_HEAVIER_CHAIN.clone();
            if let CounterproofMode::HeavierChain(ref mut heavier_chain) = input.mode {
                heavier_chain.claim_unlock_inclusion_proof.index = 1;
            }

            let _ = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        #[should_panic(expected = "claim_unlock must be included in the bridge-v1 MMR")]
        fn counterproof_invalid_if_inclusion_proof_invalid() {
            let mut input = INPUT_FOR_HEAVIER_CHAIN.clone();
            // NOTE: (@uncomputable) Because the bridge proof Moho state has 1 element,
            // the heavier chain Moho state needs at least 2 elements.
            // Otherwise, the mmr bounds check is triggered, which is tested elsewhere.
            let (heavier_moho_state, heavier_moho_proof, _inclusion_proofs) = generate_moho_state(
                [
                    BRIDGE_PROOF_CLAIM_UNLOCK.clone(),
                    HEAVIER_CHAIN_CLAIM_UNLOCK.clone(),
                ],
                HEAVIER_CHAIN_POW,
            );
            input.mode = CounterproofMode::HeavierChain(HeavierChainProof::new(
                heavier_moho_state,
                heavier_moho_proof,
                HEAVIER_CHAIN_CLAIM_UNLOCK.clone(),
                MerkleProofB32::new_zero(),
            ));

            let _ = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        #[should_panic(
            expected = "invalid heavier chain: claim unlock must be different from bridge proof"
        )]
        fn counterproof_invalid_if_claim_unlock_same() {
            let mut input = INPUT_FOR_HEAVIER_CHAIN.clone();
            let (heavier_moho_state, heavier_moho_proof, [bridge_inclusion_proof]) =
                generate_moho_state([BRIDGE_PROOF_CLAIM_UNLOCK.clone()], HEAVIER_CHAIN_POW);
            input.mode = CounterproofMode::HeavierChain(HeavierChainProof::new(
                heavier_moho_state,
                heavier_moho_proof,
                BRIDGE_PROOF_CLAIM_UNLOCK.clone(),
                bridge_inclusion_proof,
            ));

            let _ = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        fn counterproof_valid_if_heavier_chain_is_valid() {
            let input = INPUT_FOR_HEAVIER_CHAIN.clone();

            let output = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
            assert_eq!(output.game_idx, GAME_IDX.get());
            assert_eq!(output.operator_pubkey, (*OPERATOR_PUBKEY).into());
        }
    }
}
