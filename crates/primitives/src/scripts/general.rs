//! General scripts.

use std::str::FromStr;

use bitcoin::{
    absolute::LockTime,
    opcodes::all::OP_RETURN,
    script::{Builder, PushBytesBuf},
    transaction, Amount, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, Witness,
};
use bitcoin_script::{script, Script};
use miniscript::Miniscript;
use musig2::KeyAggContext;
use secp256k1::{PublicKey, XOnlyPublicKey};

use super::prelude::AuxiliaryData;

/// Create a script with the spending condition that a MuSig2 aggregated signature corresponding to
/// the pubkey set must be provided.
///
/// NOTE: This script only requires an [`XOnlyPublicKey`] which may or may not be be a musig2
/// aggregated public key. No additional validation is performed on the key.
pub fn n_of_n_script(aggregated_pubkey: &XOnlyPublicKey) -> Script {
    script! {
        { *aggregated_pubkey }
        OP_CHECKSIG
    }
}

/// Creates a "take back" script that is used to validate a deposit request transaction (DRT) given
/// a user's public key.
///
/// The `refund_delay` should be provided by the consensus-critical parameters that dictate the
/// behavior of the bridge node.
///
/// TLDR: use the `refund_delay` in the `PegOutGraphParams` inside the `Params`.
pub fn drt_take_back(recovery_xonly_pubkey: XOnlyPublicKey, refund_delay: u16) -> ScriptBuf {
    let script = format!("and_v(v:pk({recovery_xonly_pubkey}),older({refund_delay}))",);
    let miniscript = Miniscript::<XOnlyPublicKey, miniscript::Tap>::from_str(&script).unwrap();
    miniscript.encode()
}

/// Creates a script with the spending condition that a MuSig2 aggregated signature corresponding to
/// the pubkey set must be provided and the timelock is satisfied.
pub fn n_of_n_with_timelock(aggregated_pubkey: &XOnlyPublicKey, timelock: u32) -> Script {
    script! {
        { timelock }
        OP_CSV
        OP_DROP
        { *aggregated_pubkey}
        OP_CHECKSIG
    }
}

/// Creates a script that returns a nonce.
pub fn op_return_nonce(data: &[u8]) -> ScriptBuf {
    let mut push_data = PushBytesBuf::new();
    push_data
        .extend_from_slice(data)
        .expect("data should be within limit");

    Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(push_data)
        .into_script()
}

/// Aggregate the pubkeys using [`musig2`] and return the resulting [`XOnlyPublicKey`].
///
/// Please refer to MuSig2 key aggregation section in
/// [BIP 327](https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki).
pub fn get_aggregated_pubkey(pubkeys: impl IntoIterator<Item = PublicKey>) -> XOnlyPublicKey {
    let key_agg_ctx = KeyAggContext::new(pubkeys).expect("key aggregation of musig2 pubkeys");

    let aggregated_pubkey: PublicKey = key_agg_ctx.aggregated_pubkey();

    aggregated_pubkey.x_only_public_key().0
}

/// Create the metadata script that "stores" all the required metadata information for both the
/// deposit request transaction (DRT) and deposit transaction (DT).
pub fn metadata_script(auxiliary_data: AuxiliaryData) -> ScriptBuf {
    let bytes = auxiliary_data.to_vec();

    let mut data = PushBytesBuf::new();

    data.extend_from_slice(&bytes)
        .expect("bytes should be within the limit");

    Builder::new()
        .push_opcode(OP_RETURN)
        .push_slice(data)
        .into_script()
}

/// Creates a script that can be spent by anyone.
pub fn anyone_can_spend_script() -> ScriptBuf {
    script! {
        OP_TRUE
    }
    .compile()
}

/// Create an output that can be spent by anyone, i.e. its script contains a single `OP_TRUE`.
pub fn anyone_can_spend_txout() -> TxOut {
    let script = anyone_can_spend_script();
    let script_pubkey = script.to_p2wsh();
    let value = script_pubkey.minimal_non_dust();

    TxOut {
        script_pubkey,
        value,
    }
}

/// Create a bitcoin [`Transaction`] for the given inputs and outputs.
pub const fn create_tx(tx_ins: Vec<TxIn>, tx_outs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: tx_ins,
        output: tx_outs,
    }
}

/// Create a list of [`TxIn`]'s from given [`OutPoint`]'s.
///
/// This wraps the [`OutPoint`] in a structure that includes an empty `witness`, an empty
/// `script_sig` and the `sequence` set to enable replace-by-fee with no locktime.
pub fn create_tx_ins(utxos: impl IntoIterator<Item = OutPoint>) -> Vec<TxIn> {
    let mut tx_ins = Vec::new();

    for utxo in utxos {
        tx_ins.push(TxIn {
            previous_output: utxo,
            sequence: bitcoin::transaction::Sequence::ENABLE_RBF_NO_LOCKTIME,
            script_sig: ScriptBuf::default(),
            witness: Witness::new(),
        });
    }

    tx_ins
}

/// Create a list of [`TxOut`]'s' based on pairs of scripts and corresponding amounts.
pub fn create_tx_outs(
    scripts_and_amounts: impl IntoIterator<Item = (ScriptBuf, Amount)>,
) -> Vec<TxOut> {
    scripts_and_amounts
        .into_iter()
        .map(|(script_pubkey, value)| TxOut {
            script_pubkey,
            value,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use musig2::{
        aggregate_partial_signatures, sign_partial, AggNonce, PartialSignature, SecNonce,
    };
    use secp256k1::{generate_keypair, rand::rngs::OsRng, Message, SECP256K1};

    use super::*;

    #[test]
    fn test_agg_pubkey_single() {
        let (secret_key, public_key) = generate_keypair(&mut OsRng);
        let keypair = secret_key.keypair(SECP256K1);
        let key_agg_ctx =
            KeyAggContext::new([public_key]).expect("must be able to aggregate a single pubkey");

        let agg_pubkey: XOnlyPublicKey = get_aggregated_pubkey(vec![public_key]);

        assert_ne!(agg_pubkey, public_key.x_only_public_key().0);

        let data = [0u8; 32];
        let message = Message::from_digest_slice(&data).expect("must be valid");

        let signature = SECP256K1.sign_schnorr(&message, &keypair);
        assert!(SECP256K1
            .verify_schnorr(&signature, &message, &public_key.x_only_public_key().0)
            .is_ok());

        let signature = SECP256K1.sign_schnorr(&message, &keypair);
        assert!(SECP256K1
            .verify_schnorr(&signature, &message, &agg_pubkey)
            .is_err());

        let public_key: PublicKey = key_agg_ctx.aggregated_pubkey();
        let secnonce = SecNonce::build(data)
            .with_seckey(secret_key)
            .with_message(&data)
            .with_aggregated_pubkey(public_key)
            .build();
        let pubnonce = secnonce.public_nonce();
        let agg_nonce: AggNonce = [pubnonce].iter().cloned().sum();

        let partial_sig: PartialSignature = sign_partial(
            &key_agg_ctx,
            secret_key,
            secnonce,
            &agg_nonce,
            message.as_ref(),
        )
        .expect("must be able to sign with partial signature");

        let agg_sig =
            aggregate_partial_signatures(&key_agg_ctx, &agg_nonce, [partial_sig], message.as_ref())
                .expect("must be able to aggregate partial signatures");
        assert!(SECP256K1
            .verify_schnorr(&agg_sig, &message, &agg_pubkey)
            .is_ok());
    }
}
