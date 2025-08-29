use bitcoin::{
    consensus::deserialize,
    key::{Keypair, Secp256k1},
    secp256k1::{self, schnorr},
    sighash, XOnlyPublicKey,
};
use strata_crypto::groth16_verifier;
use strata_primitives::{buf::Buf32, proof::RollupVerifyingKey};
use zkaleido::{Proof, ProofReceipt, PublicValues};

use crate::{CounterproofInputBorsh, CounterproofMode, CounterproofPublicOutput};

/// Takes witness data; returns public inputs that match given witness.
/// Fails if witness is invalid.
///
/// Verification will check if
/// 1. Witness is valid (matches program), and
/// 2. Witness matches expected public inputs.
pub(crate) fn process_counterproof(
    input: CounterproofInputBorsh,
) -> Result<CounterproofPublicOutput, &'static str> {
    let CounterproofInputBorsh {
        bridge_proof_master_key,
        deposit_index,
        bridge_proof_tx_bytes,
        bridge_proof_prevouts,
        mode,
    } = input;

    // Deserialize the transaction
    let bridge_proof_tx = deserialize::<bitcoin::Transaction>(&bridge_proof_tx_bytes)
        .map_err(|_| "failed to deserialize bridge proof transaction")?;

    // Deserialize the prevouts
    let bridge_proof_prevouts: Result<Vec<bitcoin::TxOut>, _> = bridge_proof_prevouts
        .iter()
        .map(|bytes| deserialize(bytes))
        .collect();
    let bridge_proof_prevouts =
        bridge_proof_prevouts.map_err(|_| "failed to deserialize bridge proof prevouts")?;

    // Convert master key bytes back to XOnlyPublicKey
    let bridge_proof_master_key = secp256k1::XOnlyPublicKey::from_slice(&bridge_proof_master_key)
        .map_err(|_| "invalid bridge proof master key")?;

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
    // FIXME: Extract pow from public values
    let mut public_values = [0; 36];
    public_values.copy_from_slice(&bridge_proof_data[0..36]);
    let mut acc_pow_high_bytes = [0; 4];
    acc_pow_high_bytes.copy_from_slice(&bridge_proof_data[32..32 + 4]);
    let acc_pow_high_bytes = u32::from_be_bytes(acc_pow_high_bytes);
    // TODO: Reduce to 128 bytes using compressed Groth proof
    //       This requires changes in zkaleido
    let mut bridge_proof_bytes = [0; 256];
    bridge_proof_bytes.copy_from_slice(&bridge_proof_data[32 + 4..]);

    match mode {
        CounterproofMode::InvalidBridgeProof => {
            let proof = Proof::new(bridge_proof_bytes.to_vec());
            // FIXME: Create public values from bridge proof tx
            // Same number of bytes as bridge proof public values
            let public_values = PublicValues::new(Vec::new());
            let proof_receipt = ProofReceipt::new(proof, public_values);
            // TODO: Move Buf32 into constant (Buf32::new needs to become const fn first)
            // TODO: Add SP1 key of dummy statement for testing
            //       We need a valid proof and an invalid proof for the given statement to put into
            // the bridge proof tx.
            let proof_vk = RollupVerifyingKey::SP1VerifyingKey(Buf32::new([0x00; 32]));
            if groth16_verifier::verify_rollup_groth16_proof_receipt(&proof_receipt, &proof_vk)
                .is_ok()
            {
                return Err("bridge proof should be invalid for counterproof to be valid");
            }
        }
        CounterproofMode::HeavierChain(heavier_chain) => {
            let heavier_acc_pow = verify_header_chain(heavier_chain)?;
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
        bridge_proof_master_key: bridge_proof_master_key.serialize(),
        deposit_index,
    })
}

/// Verifies that the given header chain is valid under Bitcoin consensus rules.
/// Returns the accumulated proof of work.
fn verify_header_chain(_chain: Vec<[u8; 80]>) -> Result<bitcoin::Work, &'static str> {
    // TODO: Construct header verification state without requiring rollup parameters.
    //       This function does NOT care about any L2 stuff!
    // TODO: Verify genesis header: not infinite pow
    //       Latest part of recursive proof
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
    // OP_RETURN OP_PUSHDATA2 <32 + 4 + 256 = 292> (292 additional bytes...)
    //  32 bytes: tip hash
    //   4 bytes: accumulated proof of work (high bytes)
    // 256 bytes: Groth16 proof
    // Total length = 2 + 2 + 292 = 296
    if script.as_bytes().len() != 296 {
        return Err("OP_RETURN script must push exactly 292 bytes");
    }
    let data = &script.as_bytes()[2 + 2..];
    debug_assert_eq!(data.len(), 292);

    Ok(data)
}

/// Internal helper: build the LE scalar tweak from deposit_index (padded to 32 bytes).
fn deposit_index_tweak(deposit_index: u32) -> secp256k1::Scalar {
    let mut le = [0u8; 32];
    le[..4].copy_from_slice(&deposit_index.to_le_bytes());
    secp256k1::Scalar::from_le_bytes(le).expect("invalid deposit index scalar")
}

/// Derive the deposit x-only public key from a master x-only public key and a deposit index,
/// using the same LE-scalar tweak convention as `create_mock_transaction`.
///
/// NOTE: This uses the BIP340/x-only public tweak rule (normalize to even-Y before adding tweak),
/// so your signing path must also use `Keypair::add_xonly_tweak` to match.
fn derive_deposit_xonly_pubkey(
    master_xonly: &XOnlyPublicKey,
    deposit_index: u32,
) -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let tweak = deposit_index_tweak(deposit_index);

    // On modern secp256k1 versions this returns TweakedPublicKey; on some it returns
    // (XOnlyPublicKey, Parity). Adjust the pattern to your crate version if needed.
    let (tweaked, _parity) = master_xonly
        .add_tweak(&secp, &tweak)
        .expect("deposit index is invalid tweak for this pubkey");

    tweaked
}

/// Derive the **signing keypair** for the deposit by applying the same x-only tweak logic
/// to the master secret key. This MUST be used when producing the Schnorr signature,
/// or verification against `derive_deposit_xonly_pubkey` will fail.
///
/// Implementation:
/// 1) Build a Keypair from the master secret.
/// 2) Apply the same x-only tweak via `Keypair::add_xonly_tweak` (handles even-Y normalization).
fn derive_deposit_tweaked_keypair(
    master_secret_key_bytes: &[u8; 32],
    deposit_index: u32,
) -> Keypair {
    let secp = Secp256k1::new();

    let master_sk =
        secp256k1::SecretKey::from_slice(master_secret_key_bytes).expect("invalid master secret");

    let master_kp = Keypair::from_secret_key(&secp, &master_sk);

    let tweak = deposit_index_tweak(deposit_index);

    // IMPORTANT: use Keypair::add_xonly_tweak (NOT SecretKey::add_tweak).
    // This keeps signing and verification consistent under BIP340.
    master_kp
        .add_xonly_tweak(&secp, &tweak)
        .expect("deposit index is invalid tweak for this keypair")
}

/// Build a deterministic mock Taproot key-spend transaction.
/// This mock is good enough for testing SighashCache with SIGHASH_DEFAULT.
pub(crate) fn create_mock_transaction(
    bridge_proof_master_key: [u8; 32],
    deposit_index: u32,
) -> (bitcoin::Transaction, Vec<bitcoin::TxOut>) {
    use bitcoin::{
        absolute::LockTime,
        blockdata::{
            opcodes::all::OP_RETURN,
            script::{Builder, PushBytesBuf},
        },
        hashes::Hash,
        key::Secp256k1,
        sighash,
        transaction::Version,
        Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    };

    // Create transaction structure
    let prev_txid = Txid::from_slice(&[0x11u8; 32]).expect("32 bytes");
    let prevout = TxOut {
        value: Amount::from_sat(1000),
        script_pubkey: ScriptBuf::new(), // Empty script for Taproot key-spend
    };

    let txin = TxIn {
        previous_output: OutPoint {
            txid: prev_txid,
            vout: 0,
        },
        script_sig: ScriptBuf::new(),
        sequence: Sequence::from_consensus(0xFFFFFFFD),
        witness: Witness::new(), // Empty for now
    };

    // Create OP_RETURN output with 292 bytes of data (as expected by extract_op_return_data)
    let payload = [0x42u8; 292]; // Same payload as test_extract_op_return_data_valid
    let mut push_data = PushBytesBuf::new();
    push_data.extend_from_slice(&payload).expect("should fit");

    let script = Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(push_data)
        .into_script();

    let txout = TxOut {
        value: Amount::ZERO,
        script_pubkey: script,
    };

    let mut tx = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![txin],
        output: vec![txout],
    };

    let prevouts = vec![prevout];

    let secp = Secp256k1::new();
    let signing_kp = derive_deposit_tweaked_keypair(&bridge_proof_master_key, deposit_index); // ✅

    // Calculate the sighash and sign
    let mut cache = sighash::SighashCache::new(&tx);
    let sighash = cache
        .taproot_key_spend_signature_hash(
            0,
            &sighash::Prevouts::All(prevouts.as_ref()),
            bitcoin::TapSighashType::Default,
        )
        .expect("taproot sighash error");

    let msg = secp256k1::Message::from(sighash);
    let signature = secp.sign_schnorr(&msg, &signing_kp);

    // Add the signature to the witness
    let mut witness = Witness::new();
    witness.push(signature.as_ref());
    tx.input[0].witness = witness;

    (tx, prevouts)
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        key::{Keypair, Secp256k1},
        secp256k1::{Scalar, SecretKey},
        Witness, XOnlyPublicKey,
    };

    use super::*;

    #[test]
    fn test_extract_op_return_data_valid() {
        let bridge_proof_master_key = [0x01; 32];
        let deposit_index = 32u32;
        let (mock_tx, _prevouts) = create_mock_transaction(bridge_proof_master_key, deposit_index);

        let mock_result = extract_op_return_data(&mock_tx.output[0]).unwrap();
        assert_eq!(mock_result.len(), 292);
    }

    #[test]
    fn test_extract_schnorr_signature_sighash_default_with_dummy_data() {
        let secp = Secp256k1::new();

        // Make a dummy 32-byte message hash
        let msg = secp256k1::Message::from_digest_slice(&[42u8; 32]).unwrap();

        // Generate a random keypair for signing
        let keypair = secp256k1::Keypair::new(&secp, &mut secp256k1::rand::thread_rng());

        // Create a valid Schnorr signature (64 bytes)
        let sig = secp.sign_schnorr(&msg, &keypair);

        // Put the raw signature bytes into a Witness
        let mut witness = Witness::new();
        witness.push(sig.as_ref());

        // Call the extractor
        let extracted = extract_schnorr_signature_sighash_default(&witness).expect("must succeed");

        // Check it matches
        assert_eq!(extracted, sig);
    }

    /// Derive the deposit x-only public key from a master secret key and a deposit index,
    /// using the same LE-scalar tweak convention as `create_mock_transaction`.
    fn derive_deposit_xonly_pubkey(
        master_xonly: &XOnlyPublicKey,
        deposit_index: u32,
    ) -> XOnlyPublicKey {
        // deposit_index as little-endian scalar padded to 32 bytes
        let mut le = [0u8; 32];
        le[..4].copy_from_slice(&deposit_index.to_le_bytes());
        let tweak = Scalar::from_le_bytes(le).expect("invalid deposit index scalar");

        let secp = Secp256k1::new();
        let (tweaked, _parity) = master_xonly
            .add_tweak(&secp, &tweak)
            .expect("deposit index is invalid tweak for this pubkey");
        tweaked
    }
    #[test]
    fn test_create_mock_transaction() {
        use bitcoin::sighash;

        const DEPOSIT_INDEX: u32 = 32;
        let bridge_proof_master_key = [0x01; 32];

        // -- Build master x-only pubkey for verification helper
        let secp = Secp256k1::new();
        let sk = secp256k1::SecretKey::from_slice(&bridge_proof_master_key).unwrap();
        let kp = secp256k1::Keypair::from_secret_key(&secp, &sk);
        let master_xonly = XOnlyPublicKey::from_keypair(&kp).0;

        // --- create the tx (unchanged signature)
        // IMPORTANT: Inside `create_mock_transaction`, when you sign, you must now use:
        //     let signing_kp = derive_deposit_tweaked_keypair(&bridge_proof_master_key,
        // DEPOSIT_INDEX);
        //
        // And then sign with that tweaked keypair:
        //     let sig = secp.sign_schnorr(&msg, &signing_kp);
        //
        // Do NOT use: master_sk.add_tweak(...) + Keypair::from_secret_key(...)

        let (tx, prevouts) = create_mock_transaction(bridge_proof_master_key, DEPOSIT_INDEX);

        // --- verify
        let sig = extract_schnorr_signature_sighash_default(&tx.input[0].witness)
            .expect("failed to extract schnorr signature");

        let mut cache = sighash::SighashCache::new(&tx);
        let sighash = cache
            .taproot_key_spend_signature_hash(
                0,
                &sighash::Prevouts::All(prevouts.as_ref()),
                bitcoin::TapSighashType::Default,
            )
            .expect("taproot sighash error");

        let msg = secp256k1::Message::from(sighash);

        // ✅ Derive the verification key using the public x-only tweak path
        let deposit_key = derive_deposit_xonly_pubkey(&master_xonly, DEPOSIT_INDEX);

        secp.verify_schnorr(&sig, &msg, &deposit_key)
            .expect("schnorr signature verification failed");

        let extracted_data = extract_op_return_data(&tx.output[0])
            .expect("should extract OP_RETURN data successfully");
        assert_eq!(extracted_data.len(), 292);
    }
}
