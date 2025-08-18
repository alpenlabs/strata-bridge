use std::sync::Arc;

use crate::{
    error::{BridgeProofError, BridgeRelatedTx, ChainStateError},
    tx_info::{extract_valid_chainstate_from_checkpoint, extract_withdrawal_info, WithdrawalInfo},
    BridgeProofInputBorsh, BridgeProofPublicOutput,
};
use alpen_bridge_params::prelude::PegOutGraphParams;
use bitcoin::secp256k1::schnorr;
use bitcoin::{block::Header, params::Params, secp256k1, sighash, taproot};
use strata_bridge_proof_primitives::L1TxWithProofBundle;
use strata_crypto::groth16_verifier;
use strata_crypto::verify_schnorr_sig;
use strata_primitives::params::RollupParams;
use strata_primitives::prelude::Buf32;
use strata_primitives::proof::RollupVerifyingKey;
use strata_proofimpl_btc_blockspace::tx::compute_txid;
use strata_state::bridge_state::DepositState;
use zkaleido::{Proof, ProofReceipt, PublicValues};

/// The number of headers after withdrawal fulfillment transaction that must be provided as private
/// input.
///
/// This is essentially the number of headers in the chain fragment used in the proof.
/// The longer it is the harder it is to mine privately.
// TODO: (@prajwolrg, @Rajil1213) update this once this is finalized.
// It's fine to have a smaller value in testnet-I since we run the bridge nodes and they're
// incapable of constructing a private fork but this needs to be higher for mainnet (at least in the
// BitVM-based bridge design).
// The reason for choosing a lower value is that we want the bridge node
// to be able to generate the proof immediately when it needs to i.e., after it is challenged and
// the timelock between the `Claim` and `PreAssert` transaction has expired, without having to wait
// for a long time for the bitcoin chain to have enough headers after the withdrawal fulfillment
// transaction. This means that this needs to be set to a value that is lower than the
// `pre_assert_timelock` in the bridge params. To facilitate local testing, this has been sent to a
// much smaller value of `10`.
pub const REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX: usize = 10;

/// Verifies that the given transaction is included in the provided Bitcoin header's merkle root.
/// Also optionally checks if the transaction includes witness data.
///
/// # Arguments
///
/// * `tx` - The transaction bundle containing proof information.
/// * `tx_marker` - Identifies the type of transaction (checkpoint, withdrawal, or claim).
/// * `header` - The Bitcoin block header in which the transaction is purportedly included.
/// * `expect_witness` - A boolean indicating whether the transaction must include witness data.
///
/// # Errors
///
/// Returns a `BridgeProofError::InvalidMerkleProof` if:
/// - The witness data is expected but missing.
/// - The merkle proof fails verification against the provided header.
fn verify_tx_inclusion(
    tx: &L1TxWithProofBundle,
    tx_marker: BridgeRelatedTx,
    header: Header,
    expect_witness: bool,
) -> Result<(), BridgeProofError> {
    // If the transaction is expected to carry witness data, ensure it is present.
    if expect_witness && tx.get_witness_tx().is_none() {
        return Err(BridgeProofError::InvalidMerkleProof(tx_marker));
    }

    // Verify the merkle proof against the header. If verification fails, return an error.
    if !tx.verify(header) {
        return Err(BridgeProofError::InvalidMerkleProof(tx_marker));
    }

    Ok(())
}

/// Processes the verification of all transactions and chain state necessary for a bridge proof.
///
/// # Arguments
///
/// * `input` - The input data for the bridge proof, containing transactions and state information.
/// * `headers` - A sequence of Bitcoin headers that should include the transactions in question.
/// * `rollup_params` - Configuration parameters for the Strata Rollup.
///
/// # Returns
///
/// If successful, returns a tuple consisting of:
/// - `BridgeProofOutput` containing essential proof-related output data.
/// - `BatchCheckpoint` representing the Strata checkpoint.
pub(crate) fn process_bridge_proof(
    input: BridgeProofInputBorsh,
    headers: Vec<Header>,
    rollup_params: RollupParams,
    peg_out_graph_params: PegOutGraphParams,
) -> Result<BridgeProofPublicOutput, BridgeProofError> {
    // 1a. Extract valid chainstate from checkpoint.
    let (strata_checkpoint_tx, strata_checkpoint_idx) = &input.strata_checkpoint_tx;
    let chainstate = extract_valid_chainstate_from_checkpoint(
        strata_checkpoint_tx.transaction(),
        &rollup_params,
    )?;
    let mut header_vs = chainstate.l1_view().header_vs().clone();

    // 1b. Verify that the checkpoint transaction is included in the provided header chain. Since
    // the checkpoint info relies on witness data, `expect_witness` must be `true`.
    verify_tx_inclusion(
        strata_checkpoint_tx,
        BridgeRelatedTx::StrataCheckpoint,
        headers[*strata_checkpoint_idx],
        true,
    )?;

    // 3a. Extract withdrawal fulfillment info.
    let (withdrawal_fulfillment_tx, withdrawal_fulfillment_idx) = &input.withdrawal_fulfillment_tx;
    let WithdrawalInfo {
        operator_idx,
        deposit_idx,
        deposit_txid,
        withdrawal_address: destination,
        withdrawal_amount: amount,
        ..
    } = extract_withdrawal_info(
        withdrawal_fulfillment_tx.transaction(),
        peg_out_graph_params.tag,
    )?;

    // 3b. Verify the inclusion of the withdrawal fulfillment transaction in the header chain. The
    // transaction does not depend on witness data, hence `expect_witness` is `false`.
    verify_tx_inclusion(
        withdrawal_fulfillment_tx,
        BridgeRelatedTx::WithdrawalFulfillment("".to_string()),
        headers[*withdrawal_fulfillment_idx],
        false,
    )?;

    // 3c. Extract the withdrawal output from the chain state using the specified
    // deposit index.
    let entry = chainstate
        .deposits_table()
        .get_deposit(deposit_idx)
        .ok_or(ChainStateError::DepositNotFound(deposit_idx))?;

    let deposit_txid_in_chainstate = entry.output().outpoint().txid;
    if deposit_txid_in_chainstate != deposit_txid {
        Err(ChainStateError::MismatchedDepositTxid {
            deposit_txid_in_chainstate,
            deposit_txid_in_fulfillment: deposit_txid,
        })?;
    }

    let dispatched_state = match entry.deposit_state() {
        DepositState::Dispatched(dispatched_state) => dispatched_state,
        _ => return Err(ChainStateError::InvalidDepositState.into()),
    };
    let withdrawal = dispatched_state.cmd().withdraw_outputs().first().unwrap();

    // 3d. Ensure that the withdrawal information(operator, destination address and amount) matches
    // with the chain state withdrawal output.
    if operator_idx != dispatched_state.assignee()
        || destination != *withdrawal.destination().to_script()
        || amount + peg_out_graph_params.operator_fee.into() != entry.amt()
    {
        return Err(BridgeProofError::InvalidWithdrawalData);
    }

    // 3e. Ensure that the withdrawal was fulfilled before the deadline
    let withdrawal_fulfillment_height =
        header_vs.last_verified_block.height() as usize + withdrawal_fulfillment_idx;
    if withdrawal_fulfillment_height > dispatched_state.exec_deadline() as usize {
        return Err(BridgeProofError::DeadlineExceeded);
    }

    // 4a. Extract the public key of the operator who did the withdrawal fulfillment
    let operator_pub_key = chainstate
        .operator_table()
        .get_operator(operator_idx)
        // TODO: optimization, maybe use `entry_at_pos` to avoid searching
        // Deferred for now because the number of operators will be small
        .unwrap()
        .wallet_pk();

    // 4b. Verify the signature against the operator pub key in the chain state
    let withdrawal_fulfillment_txid = compute_txid(withdrawal_fulfillment_tx.transaction());
    if !verify_schnorr_sig(
        &input.op_signature,
        &withdrawal_fulfillment_txid,
        operator_pub_key,
    ) {
        return Err(BridgeProofError::InvalidOperatorSignature);
    }

    // 6. Ensure that the transactions are in order
    if strata_checkpoint_idx > withdrawal_fulfillment_idx {
        return Err(BridgeProofError::InvalidTxOrder(
            BridgeRelatedTx::StrataCheckpoint,
            BridgeRelatedTx::WithdrawalFulfillment("".to_string()),
        ));
    }

    // 7. Verify that each provided header follows Bitcoin consensus rules. This step ensures the
    //    headers are internally consistent and continuous.
    let btc_params = Params::new(rollup_params.network);
    for header in &headers {
        header_vs.check_and_update_continuity(header, &btc_params)?;
    }

    // 8. Verify sufficient headers after claim transaction
    let headers_after_withdrawal_fulfillment_tx = headers.len() - *withdrawal_fulfillment_idx;
    if headers_after_withdrawal_fulfillment_tx
        < REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX
    {
        return Err(
            BridgeProofError::InsufficientBlocksAfterWithdrawalFulfillment(
                REQUIRED_NUM_OF_HEADERS_AFTER_WITHDRAWAL_FULFILLMENT_TX,
                headers_after_withdrawal_fulfillment_tx,
            ),
        );
    }

    // 8. Construct the proof output.
    let output = BridgeProofPublicOutput {
        deposit_txid: deposit_txid.into(),
        withdrawal_fulfillment_txid,
    };

    Ok(output)
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) enum CounterproofMode {
    InvalidBridgeProof,
    HeavierChain(Arc<[bitcoin::block::Header]>),
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) struct CounterproofInput {
    bridge_proof_master_key: secp256k1::XOnlyPublicKey,
    deposit_index: u32,
    bridge_proof_tx: bitcoin::Transaction,
    bridge_proof_prevouts: Arc<[bitcoin::TxOut]>,
    mode: CounterproofMode,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub(crate) struct CounterproofPublicOutput {
    bridge_proof_master_key: secp256k1::XOnlyPublicKey,
    deposit_index: u32,
}

/// Takes witness data; returns public inputs that match given witness.
/// Fails if witness is invalid.
///
/// Verification will check if
/// 1. Witness is valid (matches program), and
/// 2. Witness matches expected public inputs.
pub(crate) fn process_counterproof<'a>(
    input: CounterproofInput,
) -> Result<CounterproofPublicOutput, &'static str> {
    let CounterproofInput {
        bridge_proof_master_key,
        deposit_index,
        bridge_proof_tx,
        bridge_proof_prevouts,
        mode,
    } = input;

    let mut deposit_index_le_bytes = [0; 32];
    deposit_index_le_bytes[0..4].copy_from_slice(&deposit_index.to_le_bytes());
    let deposit_index_scalar = match secp256k1::Scalar::from_le_bytes(deposit_index_le_bytes) {
        Ok(scalar) => scalar,
        Err(_) => unreachable!(),
    };

    let bridge_proof_deposit_key = match bridge_proof_master_key.add_tweak(secp256k1::SECP256K1, &deposit_index_scalar) {
        Ok((key, _parity)) => key,
        Err(_) => return Err("deposit index is negation of discrete logarithm of bridge proof master key (this is impossible for secure a master key)"),
    };

    if bridge_proof_tx.input.is_empty() {
        return Err("bridge proof transaction must have at least one input");
    }

    let bridge_proof_signature =
        extract_schnorr_signature_sighash_default(&bridge_proof_tx.input[0].witness)?;

    let mut sighash_cache = sighash::SighashCache::new(&bridge_proof_tx);
    let bridge_proof_sighash = sighash_cache
        .taproot_key_spend_signature_hash(
            0,
            &sighash::Prevouts::All(bridge_proof_prevouts.as_ref()),
            bitcoin::TapSighashType::Default,
        )
        .map_err(|_| "taproot error")?;

    let bridge_proof_sighash_msg = secp256k1::Message::from(bridge_proof_sighash);

    if secp256k1::SECP256K1
        .verify_schnorr(
            &bridge_proof_signature,
            &bridge_proof_sighash_msg,
            &bridge_proof_deposit_key,
        )
        .is_err()
    {
        return Err("bridge proof tx failed signature check");
    }

    if bridge_proof_tx.output.is_empty() {
        return Err("bridge proof transaction must have at least one output");
    }

    let bridge_proof_data = extract_op_return_data(&bridge_proof_tx.output[0])?;
    // FIXME: Can accumulated proof of work be extracted from public values?
    let mut public_values = [0; 36];
    public_values.copy_from_slice(&bridge_proof_data[0..36]);
    let mut acc_pow_high_bytes = [0; 4];
    acc_pow_high_bytes.copy_from_slice(&bridge_proof_data[32..32 + 4]);
    let acc_pow_high_bytes = u32::from_be_bytes(acc_pow_high_bytes);
    // FIXME: Set correct length of Groth16 proof
    let mut bridge_proof_bytes = [0; 128];
    bridge_proof_bytes.copy_from_slice(&bridge_proof_data[32 + 4..]);

    match mode {
        CounterproofMode::InvalidBridgeProof => {
            let proof = Proof::new(bridge_proof_bytes.to_vec());
            // FIXME: Create public values from bridge proof tx
            let public_values = PublicValues::new(Vec::new());
            let proof_receipt = ProofReceipt::new(proof, public_values);
            // TODO: Move Buf32 into constant (Buf32::new needs to become const fn first)
            // TODO: Add SP1 key of dummy statement for testing
            //       We need a valid proof and an invalid proof for the given statement to put into the bridge proof tx.
            let rollup_vk = RollupVerifyingKey::SP1VerifyingKey(Buf32::new([0x00; 32]));
            if groth16_verifier::verify_rollup_groth16_proof_receipt(&proof_receipt, &rollup_vk)
                .is_ok()
            {
                return Err("bridge proof should be invalid for counterproof to be valid");
            }
        }
        CounterproofMode::HeavierChain(heavier_chain) => {
            let heavier_acc_pow = verify_header_chain(&heavier_chain)?;
            let x = heavier_acc_pow.to_be_bytes();
            let heavier_acc_pow_high_bytes = u32::from_be_bytes([x[0], x[1], x[2], x[3]]);
            if heavier_acc_pow_high_bytes <= acc_pow_high_bytes {
                return Err(
                    "heavier chain must have more accumulated work than the operator chain",
                );
            }
        }
    }

    Ok(CounterproofPublicOutput {
        bridge_proof_master_key,
        deposit_index,
    })
}

/// Verifies that the given header chain is valid under Bitcoin consensus rules.
/// Returns the accumulated proof of work.
fn verify_header_chain(chain: &[bitcoin::block::Header]) -> Result<bitcoin::Work, &'static str> {
    // TODO: Construct header verification state without requiring rollup parameters.
    //       This function does NOT care about any L2 stuff!
    // let btc_params = Params::new(rollup_params.network);
    // for header in &headers {
    //     header_vs.check_and_update_continuity(header, &btc_params)?;
    // }
    Ok(bitcoin::Work::from_be_bytes([0xff; 32]))
}

/// Extracts a Schnorr signature from a Taproot witness, ensuring it uses SIGHASH_DEFAULT.
fn extract_schnorr_signature_sighash_default(
    witness: &bitcoin::Witness,
) -> Result<schnorr::Signature, &'static str> {
    if witness.len() != 1 {
        return Err("witness must have length 1 (taproot key path spend)");
    }
    let sig_bytes = &witness[0];
    if sig_bytes.len() != 64 {
        return Err("sighash mode must be SIGHASH_DEFAULT, which means that the signature must be exactly 64 bytes");
    }

    schnorr::Signature::from_slice(sig_bytes).map_err(|_| "invalid signature")
}

fn extract_op_return_data(txout: &bitcoin::TxOut) -> Result<&[u8], &'static str> {
    let script = &txout.script_pubkey;
    if !script.is_op_return() {
        return Err("locking script must be an OP_RETURN script");
    }
    // OP_RETURN OP_PUSHDATA1 <32 + 4 + 128 = 164> (164 additional bytes...)
    // Total length = 3 + 164 = 167
    if script.as_bytes().len() != 167 {
        return Err("OP_RETURN script must push exactly 164 bytes");
    }
    let data = &script.as_bytes()[3..];
    debug_assert_eq!(data.len(), 164);

    Ok(data)
}
