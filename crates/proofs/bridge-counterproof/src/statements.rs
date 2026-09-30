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
use strata_asm_proto_bridge_txs::BRIDGE_SUBPROTOCOL_ID;
use strata_bridge_connectors::prelude::ContestProofConnector;
use strata_bridge_proof::BridgeProofOutput;
use strata_bridge_proof_common::{verify_claim_unlock_inclusion, verify_moho_proof};
use zkaleido::{ProofReceipt, ZkVmEnv, ZkVmEnvSsz};

#[cfg(not(target_os = "zkvm"))]
use crate::genesis::load_genesis;
use crate::{
    BridgeCounterproofGenesis, CounterproofMode, HeavierChainProof,
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
        game_idx: game_idx_raw,
        operator_pubkey: operator_pubkey_raw,
        n_of_n_pubkey: n_of_n_pubkey_raw,
        proof_timelock: proof_timelock_raw,
        bridge_proof_tx: bridge_proof_tx_raw,
        bridge_proof_tx_prevouts,
        bridge_proof_tx_input_idx,
        mode,
    } = zkvm.read_ssz();

    // ┌───────────────────────────────────────────────────────────────────────┐
    // │                             Parse inputs                              │
    // └───────────────────────────────────────────────────────────────────────┘
    let game_idx =
        NonZero::new(game_idx_raw).expect("invalid counterproof: game index cannot be zero");
    // BitcoinXOnlyPublicKey::to_xonly_public_key() should always succeed due to type invariant
    let operator_pubkey = operator_pubkey_raw.to_xonly_public_key();
    let n_of_n_pubkey = n_of_n_pubkey_raw.to_xonly_public_key();
    let proof_timelock = relative::Height::from_height(proof_timelock_raw);
    let bridge_proof_tx: Transaction = (&bridge_proof_tx_raw)
        .try_into()
        .expect("invalid counterproof: bridge proof transaction doesn't parse");
    let prevouts: Vec<TxOut> = bridge_proof_tx_prevouts
        .into_iter()
        .map(TxOut::from)
        .collect();
    assert_eq!(
        bridge_proof_tx.input.len(),
        prevouts.len(),
        "invalid counterproof: length of prevouts not equal number of transaction inputs",
    );
    // This cast always succeeds, assuming a 32-bit architecture or higher
    let input_idx = bridge_proof_tx_input_idx as usize;

    // ┌───────────────────────────────────────────────────────────────────────┐
    // │                       Verify operator signature                       │
    // └───────────────────────────────────────────────────────────────────────┘
    let signature_raw = bridge_proof_tx.input[input_idx]
        .witness
        .iter()
        .next()
        .expect("invalid counterproof: contest-proof txin: no witness");
    let signature = taproot::Signature::from_slice(signature_raw)
        .expect("invalid counterproof: contest-proof txin: signature doesn't parse");
    let mut cache = SighashCache::new(&bridge_proof_tx);
    let message = cache
        .taproot_key_spend_signature_hash(
            input_idx,
            &Prevouts::All(&prevouts),
            signature.sighash_type,
        )
        .map(Message::from)
        .expect("sighash computation should never fail");
    let output_key = ContestProofConnector::new(
        Network::Bitcoin,
        n_of_n_pubkey,
        operator_pubkey,
        game_idx,
        proof_timelock,
        Amount::ZERO,
    )
    .output_key()
    .to_x_only_public_key();

    SECP256K1
        .verify_schnorr(&signature.signature, &message, &output_key)
        .expect("invalid counterproof: contest-proof txin: signature doesn't verify");

    // ┌───────────────────────────────────────────────────────────────────────┐
    // │                         Extract bridge proof                          │
    // └───────────────────────────────────────────────────────────────────────┘
    // Immediately succeed if sighash mode is not SIGHASH_DEFAULT
    if signature.sighash_type != TapSighashType::Default {
        zkvm.commit_ssz(&CounterproofOutput {
            operator_pubkey: operator_pubkey_raw,
            game_idx: game_idx_raw,
        });
        return;
    }
    // Immediately succeed if first output doesn't exist
    let Some(output_0) = bridge_proof_tx.output.first() else {
        zkvm.commit_ssz(&CounterproofOutput {
            operator_pubkey: operator_pubkey_raw,
            game_idx: game_idx_raw,
        });
        return;
    };
    // Immediately succeed if first output has no OP_RETURN in the expected format
    let Some(output_0_payload) = extract_op_return_payload(&output_0.script_pubkey) else {
        zkvm.commit_ssz(&CounterproofOutput {
            operator_pubkey: operator_pubkey_raw,
            game_idx: game_idx_raw,
        });
        return;
    };
    // Immediately succeed if bridge proof receipt doesn't parse
    let Ok(bridge_proof_receipt) = borsh::from_slice::<ProofReceipt>(output_0_payload) else {
        zkvm.commit_ssz(&CounterproofOutput {
            operator_pubkey: operator_pubkey_raw,
            game_idx: game_idx_raw,
        });
        return;
    };
    // Immediately succeed if bridge proof output doesn't parse
    let Ok(BridgeProofOutput {
        total_pow,
        claim_unlock: unlock,
        mmr_idx,
    }) = BridgeProofOutput::from_ssz_bytes(bridge_proof_receipt.public_values().as_bytes())
    else {
        zkvm.commit_ssz(&CounterproofOutput {
            operator_pubkey: operator_pubkey_raw,
            game_idx: game_idx_raw,
        });
        return;
    };

    // ┌───────────────────────────────────────────────────────────────────────┐
    // │                          Verify claim unlock                          │
    // └───────────────────────────────────────────────────────────────────────┘
    // Immediately succeed if unlock is for a different game
    if (game_idx_raw - 1 != unlock.deposit_idx)
        || (operator_pubkey_raw.inner() != &unlock.operator_pubkey)
    {
        zkvm.commit_ssz(&CounterproofOutput {
            operator_pubkey: operator_pubkey_raw,
            game_idx: game_idx_raw,
        });
        return;
    }

    match mode {
        CounterproofMode::InvalidBridgeProof => {
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
            let HeavierChainProof {
                moho_state: heavier_moho_state,
                moho_proof: heavier_moho_proof,
                claim_unlock: heavier_claim_unlock,
                claim_unlock_inclusion_proof: heavier_inclusion_proof,
            } = heavier_chain_proof;

            // Fail if `heavier_moho_proof` is invalid.
            verify_moho_proof(
                &heavier_moho_state,
                &heavier_moho_proof,
                &genesis.genesis_moho_state,
                genesis.moho_vk.clone(),
                "invalid heavier chain: invalid moho proof",
            );

            let heavier_bridge_container = heavier_moho_state
                .export_state()
                .containers()
                .iter()
                .find(|c| c.container_id() == BRIDGE_SUBPROTOCOL_ID)
                .expect("moho_state must contain a bridge-v1 export container");

            // Fail if pow(heavier_chain) <= pow(operator_chain)
            if leq_little_endian(heavier_bridge_container.extra_data(), &total_pow) {
                panic!("invalid heavier chain: not enough proof of work");
            }

            // Immediately succeed if `mmr_idx` is out of bounds
            // for `heavier_moho_state`.
            //
            // This means that the heavier chain has fewer claim unlocks
            // than the operator chain, which means that there are fake
            // claim unlocks on the operator chain.
            //
            // The claim unlock and its inclusion proof are ignored in this case.
            if heavier_bridge_container.entries_mmr().num_entries() <= mmr_idx {
                break 'heavier_chain;
            }

            // Fail if `heavier_claim_unlock` is not at index `mmr_idx`.
            if heavier_inclusion_proof.index != mmr_idx {
                panic!("invalid heavier chain: claim unlock index must match bridge proof")
            }

            // Fail if `heavier_claim_unlock` is not included in `heavier_moho_state`.
            verify_claim_unlock_inclusion(
                &heavier_claim_unlock,
                heavier_bridge_container,
                &heavier_inclusion_proof,
                "invalid heavier chain: invalid inclusion proof for heavier claim unlock",
            );

            // Fail if `heavier_claim_unlock` is equal to `unlock`.
            //
            // If the heavier chain is an extension of the operator chain,
            // i.e. the watchtower just waited a few blocks after the operator
            // posted the bridge proof, then this equality is triggered.
            if heavier_claim_unlock == unlock {
                panic!("invalid heavier chain: claim unlock must be different from bridge proof")
            }
        }
    }

    zkvm.commit_ssz(&CounterproofOutput {
        operator_pubkey: operator_pubkey_raw,
        game_idx: game_idx_raw,
    });
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

/// Returns `true` if `lhs <= rhs` for byte arrays in little-endian format.
pub fn leq_little_endian(lhs: &[u8; 32], rhs: &[u8; 32]) -> bool {
    lhs.iter().rev().cmp(rhs.iter().rev()).is_le()
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
    use strata_asm_proto_bridge::OperatorClaimUnlockV1;
    use strata_bridge_connectors::Connector;
    use strata_bridge_proof_common::{MOHO_GENESIS_ATTESTATION, generate_moho_state};
    use strata_bridge_test_utils::bitcoin::generate_keypair;
    use strata_bridge_tx_graph::transactions::prelude::{BridgeProofData, BridgeProofTx};
    use strata_identifiers::Buf32;
    use strata_predicate::PredicateKey;
    use zkaleido::{Proof, PublicValues};
    use zkaleido_native_adapter::NativeMachine;

    use super::*;
    use crate::{BitcoinTxOut, CounterproofMode, RawBitcoinTx};

    const GAME_IDX: NonZero<u32> = NonZero::new(7).unwrap();
    const CONTESTED_DEPOSIT_IDX: u32 = GAME_IDX.get() - 1;
    const PROOF_TIMELOCK: relative::Height = relative::Height::from_height(100);
    const TXIN_IDX: u32 = 0;

    fn operator_key(n: u8) -> Buf32 {
        Buf32([n; 32])
    }

    static OPERATOR_KEYPAIR: LazyLock<Keypair> = LazyLock::new(generate_keypair);
    static OPERATOR_PUBKEY: LazyLock<XOnlyPublicKey> =
        LazyLock::new(|| OPERATOR_KEYPAIR.x_only_public_key().0);
    static OPERATOR_PUBKEY_BUF: LazyLock<Buf32> =
        LazyLock::new(|| Buf32(OPERATOR_PUBKEY.serialize()));
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
    static BRIDGE_PROOF_CLAIM_UNLOCK: LazyLock<OperatorClaimUnlockV1> =
        LazyLock::new(|| OperatorClaimUnlockV1::new(CONTESTED_DEPOSIT_IDX, *OPERATOR_PUBKEY_BUF));
    static HEAVIER_CHAIN_CLAIM_UNLOCK: LazyLock<OperatorClaimUnlockV1> =
        LazyLock::new(|| OperatorClaimUnlockV1::new(0, operator_key(1)));
    const BRIDGE_PROOF_POW: [u8; 32] = [
        0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    const HEAVIER_CHAIN_POW: [u8; 32] = [
        1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];

    fn bridge_proof_receipt(claim_unlock: &OperatorClaimUnlockV1) -> ProofReceipt {
        let output = BridgeProofOutput {
            total_pow: BRIDGE_PROOF_POW,
            claim_unlock: claim_unlock.clone(),
            mmr_idx: 0,
        };
        ProofReceipt::new(Proof::new(vec![]), PublicValues::new(output.as_ssz_bytes()))
    }

    fn bridge_proof_tx(claim_unlock: &OperatorClaimUnlockV1) -> BridgeProofTx {
        let data = BridgeProofData {
            contest_txid: Txid::all_zeros(),
            proof_bytes: borsh::to_vec(&bridge_proof_receipt(claim_unlock)).unwrap(),
            game_index: GAME_IDX,
        };

        BridgeProofTx::new(data, *CONTEST_PROOF_CONNECTOR)
    }

    fn sign_bridge_proof_tx(tx: BridgeProofTx) -> Transaction {
        let signing_info = tx.signing_info_partial();
        let tweaked_operator_key = OPERATOR_KEYPAIR
            .add_xonly_tweak(
                SECP256K1,
                &ContestProofConnector::operator_key_tweak(GAME_IDX),
            )
            .expect("game-idx tweak is valid");

        tx.finalize_partial(signing_info.sign(&tweaked_operator_key))
    }

    static BRIDGE_PROOF_TX_UNSIGNED: LazyLock<BridgeProofTx> =
        LazyLock::new(|| bridge_proof_tx(&BRIDGE_PROOF_CLAIM_UNLOCK));
    static BRIDGE_PROOF_TX_SIGNED: LazyLock<Transaction> =
        LazyLock::new(|| sign_bridge_proof_tx(BRIDGE_PROOF_TX_UNSIGNED.clone()));

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
    fn leq_little_endian_compares_pow_as_little_endian_integers() {
        let zero = [0u8; 32];
        let mut one = [0u8; 32];
        one[0] = 1; // little-endian 1

        let mut big = [0u8; 32];
        big[31] = 1; // little-endian 2^248, far larger than `one`

        assert!(leq_little_endian(&zero, &one), "0 <= 1");
        assert!(!leq_little_endian(&one, &zero), "1 is not <= 0");
        assert!(leq_little_endian(&one, &one), "equal is <=");
        assert!(
            leq_little_endian(&one, &big),
            "low-order byte does not dominate"
        );
        assert!(!leq_little_endian(&big, &one), "high-order byte dominates");
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

    static INPUT_FOR_INVALID_BRIDGE_PROOF: LazyLock<CounterproofInput> =
        LazyLock::new(|| CounterproofInput {
            game_idx: GAME_IDX.get(),
            operator_pubkey: (*OPERATOR_PUBKEY).into(),
            n_of_n_pubkey: (*N_OF_N_PUBKEY).into(),
            proof_timelock: PROOF_TIMELOCK.value(),
            bridge_proof_tx: BRIDGE_PROOF_TX_SIGNED.clone().into(),
            bridge_proof_tx_prevouts: PREVOUTS
                .iter()
                .cloned()
                .map(|prevout| {
                    BitcoinTxOut::try_from(prevout).expect("fixture prevout fits SSZ bounds")
                })
                .collect(),
            bridge_proof_tx_input_idx: TXIN_IDX,
            mode: CounterproofMode::InvalidBridgeProof,
        });

    /// Unit tests for any mode.
    ///
    /// These tests handle code that is executed before the counterproof statement splits into the
    /// different modes. For simplicity, the tests use `CounterproofMode::InvalidBridgeProof`.
    ///
    /// The tests are sorted in order of execution in the counterproof statement.
    mod any_mode {
        use super::*;

        #[test]
        #[should_panic(expected = "invalid counterproof: game index cannot be zero")]
        fn counterproof_invalid_if_game_index_zero() {
            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.game_idx = 0;

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        #[should_panic(expected = "invalid counterproof: bridge proof transaction doesn't parse")]
        fn counterproof_invalid_if_bridge_proof_tx_doesnt_parse() {
            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            let invalid_encoding = vec![0x00; 1];
            input.bridge_proof_tx = RawBitcoinTx::from_raw_bytes(invalid_encoding);

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        #[should_panic(
            expected = "invalid counterproof: length of prevouts not equal number of transaction inputs"
        )]
        fn counterproof_invalid_if_prevouts_invalid_length() {
            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.bridge_proof_tx_prevouts.clear();

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        #[should_panic(expected = "invalid counterproof: contest-proof txin: no witness")]
        fn counterproof_invalid_if_no_witness() {
            let mut tx = BRIDGE_PROOF_TX_SIGNED.clone();
            tx.input[0].witness = Witness::new();

            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.bridge_proof_tx = tx.into();

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        #[should_panic(
            expected = "invalid counterproof: contest-proof txin: signature doesn't parse"
        )]
        fn counterproof_invalid_if_signature_doesnt_parse() {
            let mut tx = BRIDGE_PROOF_TX_SIGNED.clone();
            let invalid_signature = vec![0; 1];
            tx.input[0].witness = Witness::from(vec![invalid_signature]);

            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.bridge_proof_tx = tx.into();

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        #[test]
        #[should_panic(
            expected = "invalid counterproof: contest-proof txin: signature doesn't verify"
        )]
        fn counterproof_invalid_if_signature_doesnt_verify() {
            let mut tx = BRIDGE_PROOF_TX_SIGNED.clone();
            // We make the Schnorr signature verification fail
            // by mutating a field that is covered by the sighash.
            tx.lock_time = absolute::LockTime::from_consensus(1);

            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.bridge_proof_tx = tx.into();

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
            });
        }

        // The signature is verified, so all following unit tests must contain a valid signature.
        // Remember that unit tests are sorted in the order of code execution.

        #[test]
        fn counterproof_valid_if_not_sighash_default() {
            let unsigned_tx = BRIDGE_PROOF_TX_UNSIGNED.clone();
            let signing_info =
                unsigned_tx.signing_info_partial_with_sighash_type(TapSighashType::None);
            let tweaked_operator_key = OPERATOR_KEYPAIR
                .add_xonly_tweak(
                    SECP256K1,
                    &ContestProofConnector::operator_key_tweak(GAME_IDX),
                )
                .expect("game-idx tweak is valid");
            let mut tx = unsigned_tx.finalize_partial(signing_info.sign(&tweaked_operator_key));
            // Non-default signatures must include the sighash byte in the witness.
            // We do a hotfix here.
            let mut witness = tx.input[TXIN_IDX as usize].witness.to_vec();
            witness[0].push(TapSighashType::None as u8);
            tx.input[TXIN_IDX as usize].witness = Witness::from(witness);

            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.bridge_proof_tx = tx.into();

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::never_accept(),
                moho_vk: PredicateKey::never_accept(),
            });
        }

        #[test]
        fn counterproof_valid_if_first_output_doesnt_exist() {
            let mut unsigned_tx = BRIDGE_PROOF_TX_UNSIGNED.clone();
            unsigned_tx.clear_output();
            let tx = sign_bridge_proof_tx(unsigned_tx);

            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.bridge_proof_tx = tx.into();

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::never_accept(),
                moho_vk: PredicateKey::never_accept(),
            });
        }

        #[test]
        fn counterproof_valid_if_first_output_has_malformed_op_return() {
            let mut unsigned_tx = BRIDGE_PROOF_TX_UNSIGNED.clone();
            unsigned_tx.clear_output();
            let malformed_op_return_script = ScriptBuf::new();
            unsigned_tx.push_output(TxOut {
                script_pubkey: malformed_op_return_script,
                value: Amount::ZERO,
            });
            let tx = sign_bridge_proof_tx(unsigned_tx);

            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.bridge_proof_tx = tx.into();

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::never_accept(),
                moho_vk: PredicateKey::never_accept(),
            });
        }

        #[test]
        fn counterproof_valid_if_bridge_proof_receipt_doesnt_parse() {
            let mut unsigned_tx = BRIDGE_PROOF_TX_UNSIGNED.clone();
            unsigned_tx.clear_output();
            let malformed_proof_bytes = vec![0x00];
            unsigned_tx.push_output(TxOut {
                script_pubkey: op_return_script(malformed_proof_bytes),
                value: Amount::ZERO,
            });
            let tx = sign_bridge_proof_tx(unsigned_tx);

            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.bridge_proof_tx = tx.into();

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::never_accept(),
                moho_vk: PredicateKey::never_accept(),
            });
        }

        #[test]
        fn counterproof_valid_if_bridge_proof_output_doesnt_parse() {
            let malformed_bridge_proof_output = vec![0x00];
            let receipt = ProofReceipt::new(
                Proof::new(vec![]),
                PublicValues::new(malformed_bridge_proof_output),
            );
            let data = BridgeProofData {
                contest_txid: Txid::all_zeros(),
                proof_bytes: borsh::to_vec(&receipt).unwrap(),
                game_index: GAME_IDX,
            };
            let tx = sign_bridge_proof_tx(BridgeProofTx::new(data, *CONTEST_PROOF_CONNECTOR));

            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.bridge_proof_tx = tx.into();

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::never_accept(),
            });
        }

        #[test]
        fn counterproof_valid_if_unlock_has_wrong_deposit_idx() {
            let unlock =
                OperatorClaimUnlockV1::new(CONTESTED_DEPOSIT_IDX + 1, *OPERATOR_PUBKEY_BUF);
            let tx = sign_bridge_proof_tx(bridge_proof_tx(&unlock));

            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.bridge_proof_tx = tx.into();

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::never_accept(),
            });
        }

        #[test]
        fn counterproof_valid_if_unlock_has_wrong_operator_pubkey() {
            let unlock = OperatorClaimUnlockV1::new(CONTESTED_DEPOSIT_IDX, operator_key(0));
            let tx = sign_bridge_proof_tx(bridge_proof_tx(&unlock));

            let mut input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();
            input.bridge_proof_tx = tx.into();

            run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::never_accept(),
            });
        }
    }

    /// Unit tests for `CounterproofMode::InvalidBridgeProof`.
    mod invalid_bridge_proof {
        use super::*;

        #[test]
        #[should_panic(expected = "invalid counterproof: bridge proof is valid")]
        fn counterproof_invalid_if_bridge_proof_valid() {
            let input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();

            let _ = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::never_accept(),
            });
        }

        #[test]
        fn counterproof_valid_if_bridge_proof_invalid() {
            let input = INPUT_FOR_INVALID_BRIDGE_PROOF.clone();

            let output = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::never_accept(),
                moho_vk: PredicateKey::never_accept(),
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
            bridge_proof_tx: BRIDGE_PROOF_TX_SIGNED.clone().into(),
            bridge_proof_tx_prevouts: PREVOUTS
                .iter()
                .cloned()
                .map(|prevout| {
                    BitcoinTxOut::try_from(prevout).expect("fixture prevout fits SSZ bounds")
                })
                .collect(),
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
        use moho_types::{
            MohoStateCommitment, RecursiveMohoAttestation, RecursiveMohoProof, StateRefAttestation,
        };
        use strata_merkle::MerkleProofB32;

        use super::*;

        // Re-anchors a Moho proof onto `genesis_state`, leaving the proven state untouched.
        fn reanchor(
            moho_proof: &RecursiveMohoProof,
            genesis_state: StateRefAttestation,
        ) -> RecursiveMohoProof {
            RecursiveMohoProof::new(
                RecursiveMohoAttestation::new(genesis_state, *moho_proof.attestation().proven()),
                moho_proof.proof().to_vec(),
            )
        }

        #[test]
        #[should_panic(expected = "invalid heavier chain: invalid moho proof")]
        fn counterproof_invalid_if_heavier_moho_proof_invalid() {
            let input = INPUT_FOR_HEAVIER_CHAIN.clone();

            let _ = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::never_accept(),
            });
        }

        #[test]
        #[should_panic(expected = "moho proof doesn't build on given genesis")]
        fn counterproof_invalid_if_heavier_genesis_state_forged() {
            let mut input = INPUT_FOR_HEAVIER_CHAIN.clone();
            // A genesis state of the watchtower's choosing, kept under the real genesis reference.
            let forged_genesis_state = StateRefAttestation::new(
                *MOHO_GENESIS_ATTESTATION.reference(),
                MohoStateCommitment::new([0xab; 32]),
            );
            if let CounterproofMode::HeavierChain(ref mut heavier_chain) = input.mode {
                heavier_chain.moho_proof =
                    reanchor(&heavier_chain.moho_proof, forged_genesis_state);
            }

            let _ = run_counterproof(RuntimeArgs {
                input,
                bridge_proof_vk: PredicateKey::always_accept(),
                moho_vk: PredicateKey::always_accept(),
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
        #[should_panic(
            expected = "invalid heavier chain: invalid inclusion proof for heavier claim unlock"
        )]
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
