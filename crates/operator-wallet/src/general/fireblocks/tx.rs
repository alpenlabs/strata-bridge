//! Unsigned-transaction construction for the Fireblocks backend: input selection, fee /
//! change computation, and BIP-143 sighash derivation.
//!
//! Fireblocks doesn't build Bitcoin transactions for us (we use RAW signing), so this module
//! does the work a BDK wallet would: pick P2WPKH inputs, size the fee from a predicted weight,
//! add a change output when it clears dust, and emit the unsigned v3 (TRUC) transaction plus
//! the per-input sighashes to sign.

use std::collections::HashSet;

use bdk_wallet::bitcoin::{
    hashes::Hash,
    transaction::{predict_weight, InputWeightPrediction, Version},
    Amount, EcdsaSighashType, FeeRate, OutPoint, Psbt, Script, ScriptBuf, Sequence, Transaction,
    TxIn, TxOut, Witness,
};

use super::FireblocksError;
use crate::general::UtxoInfo;

/// A chosen funding input: its outpoint and the prevout it spends (value + P2WPKH script).
#[derive(Debug, Clone)]
pub(super) struct FundingInput {
    pub outpoint: OutPoint,
    pub prevout: TxOut,
}

/// Greedily selects P2WPKH funding inputs (largest first) to cover `recipient_total` plus the
/// transaction fee at `fee_rate`, optionally appending a change output to `change_spk`.
///
/// Only UTXOs whose `script_pubkey == deposit_spk` are eligible: the backend assumes a
/// single-address vault so every input signs with the same key (see the module docs on
/// `fireblocks.rs`). `exclude` and anchors-via-`deposit_spk` filtering are applied by the
/// caller through `exclude`.
///
/// Returns the selected inputs and the change amount (`None` when the remainder is below the
/// change output's dust threshold, in which case it is absorbed into the fee).
pub(super) fn select_funding(
    candidates: &[UtxoInfo],
    exclude: &HashSet<OutPoint>,
    deposit_spk: &Script,
    recipient_outputs: &[TxOut],
    change_spk: &Script,
    fee_rate: FeeRate,
) -> Result<(Vec<FundingInput>, Option<Amount>), FireblocksError> {
    let recipient_total = recipient_outputs
        .iter()
        .try_fold(Amount::ZERO, |acc, o| acc.checked_add(o.value))
        .ok_or_else(|| FireblocksError::TxBuild("recipient output total overflows".into()))?;

    // Eligible UTXOs: at the deposit address, not excluded. Largest first to minimise input
    // count (and thus fee).
    let mut eligible: Vec<&UtxoInfo> = candidates
        .iter()
        .filter(|u| u.script_pubkey == *deposit_spk && !exclude.contains(&u.outpoint))
        .collect();
    eligible.sort_by_key(|u| std::cmp::Reverse(u.amount));

    let recipient_lens: Vec<usize> = recipient_outputs
        .iter()
        .map(|o| o.script_pubkey.len())
        .collect();
    let change_dust = change_spk.minimal_non_dust();

    let mut selected: Vec<FundingInput> = Vec::new();
    let mut total_in = Amount::ZERO;

    for u in eligible {
        selected.push(FundingInput {
            outpoint: u.outpoint,
            prevout: TxOut {
                value: u.amount,
                script_pubkey: u.script_pubkey.clone(),
            },
        });
        total_in = total_in
            .checked_add(u.amount)
            .ok_or_else(|| FireblocksError::TxBuild("input total overflows".into()))?;

        // Fee if we add a change output, and if we don't.
        let fee_with_change = fee_for(
            selected.len(),
            &recipient_lens,
            Some(change_spk.len()),
            fee_rate,
        )?;
        let fee_no_change = fee_for(selected.len(), &recipient_lens, None, fee_rate)?;

        // Enough to cover outputs + fee with a change output that clears dust?
        if let Some(rem) = total_in
            .checked_sub(recipient_total)
            .and_then(|r| r.checked_sub(fee_with_change))
        {
            if rem >= change_dust {
                return Ok((selected, Some(rem)));
            }
        }
        // Enough to cover outputs + fee with no change (remainder absorbed into fee)?
        if recipient_total
            .checked_add(fee_no_change)
            .is_some_and(|need| total_in >= need)
        {
            return Ok((selected, None));
        }
    }

    Err(FireblocksError::TxBuild(format!(
        "insufficient funds: have {total_in}, need {recipient_total} + fee"
    )))
}

/// Predicted fee for a transaction with `n_p2wpkh_inputs` P2WPKH inputs, the given recipient
/// output script lengths, and an optional change output of `change_spk_len` bytes.
pub(super) fn fee_for(
    n_p2wpkh_inputs: usize,
    recipient_output_lens: &[usize],
    change_spk_len: Option<usize>,
    fee_rate: FeeRate,
) -> Result<Amount, FireblocksError> {
    let inputs = std::iter::repeat_n(InputWeightPrediction::P2WPKH_MAX, n_p2wpkh_inputs);
    let output_lens = recipient_output_lens.iter().copied().chain(change_spk_len);
    let weight = predict_weight(inputs, output_lens);
    fee_rate
        .fee_wu(weight)
        .ok_or_else(|| FireblocksError::TxBuild("fee computation overflowed".into()))
}

/// Predicted vsize of a CPFP child with `n_p2wpkh` P2WPKH inputs, optionally preceded by a
/// P2TR key-spend anchor input (the foreign keyed anchor for an `AnchorBearing` parent),
/// plus a single change output. When `has_p2tr_anchor` is false every input is P2WPKH (the
/// `ParentTxCombined` case where the combined input is the operator's own vault output).
pub(super) fn cpfp_child_vsize(
    n_p2wpkh: usize,
    has_p2tr_anchor: bool,
    change_spk_len: usize,
) -> u64 {
    let anchor = has_p2tr_anchor.then_some(InputWeightPrediction::P2TR_KEY_DEFAULT_SIGHASH);
    let inputs = anchor.into_iter().chain(std::iter::repeat_n(
        InputWeightPrediction::P2WPKH_MAX,
        n_p2wpkh,
    ));
    predict_weight(inputs, [change_spk_len]).to_vbytes_ceil()
}

/// Assembles the unsigned v3 (TRUC) transaction from already-chosen inputs and outputs.
///
/// Inputs are emitted in the given order with empty witnesses and RBF-signalling sequences;
/// `recipient_outputs` come first, followed by the change output (if `change` is `Some`).
pub(super) fn build_unsigned_v3(
    inputs: &[TxIn],
    recipient_outputs: Vec<TxOut>,
    change: Option<TxOut>,
) -> Transaction {
    let mut output = recipient_outputs;
    if let Some(change) = change {
        output.push(change);
    }
    Transaction {
        version: Version(3),
        lock_time: bdk_wallet::bitcoin::absolute::LockTime::ZERO,
        input: inputs.to_vec(),
        output,
    }
}

/// Builds a [`TxIn`] spending `outpoint` with an RBF-signalling sequence and an empty witness.
pub(super) const fn txin(outpoint: OutPoint) -> TxIn {
    TxIn {
        previous_output: outpoint,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    }
}

/// Computes the BIP-143 sighash (SIGHASH_ALL) for the P2WPKH input at `input_index` of
/// `psbt`'s unsigned transaction. `prevouts[i]` must be the output spent by input `i`.
pub(super) fn p2wpkh_sighash(
    psbt: &Psbt,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 32], FireblocksError> {
    let prevout = prevouts
        .get(input_index)
        .ok_or_else(|| FireblocksError::TxBuild(format!("no prevout for input {input_index}")))?;
    let mut cache = bdk_wallet::bitcoin::sighash::SighashCache::new(&psbt.unsigned_tx);
    let sighash = cache
        .p2wpkh_signature_hash(
            input_index,
            &prevout.script_pubkey,
            prevout.value,
            EcdsaSighashType::All,
        )
        .map_err(|e| {
            FireblocksError::TxBuild(format!("p2wpkh sighash (input {input_index}): {e}"))
        })?;
    Ok(sighash.to_byte_array())
}

#[cfg(test)]
mod tests {
    use bdk_wallet::bitcoin::{
        hashes::Hash, key::Secp256k1, Address, Network, Txid, XOnlyPublicKey,
    };

    use super::*;

    fn deposit_spk() -> ScriptBuf {
        let kp =
            bdk_wallet::bitcoin::key::Keypair::from_seckey_slice(&Secp256k1::new(), &[7u8; 32])
                .unwrap();
        let (xonly, _) = XOnlyPublicKey::from_keypair(&kp);
        // A P2WPKH address derived from a compressed key.
        let pk = bdk_wallet::bitcoin::PublicKey::new(kp.public_key());
        let _ = xonly;
        Address::p2wpkh(
            &bdk_wallet::bitcoin::CompressedPublicKey(pk.inner),
            Network::Regtest,
        )
        .script_pubkey()
    }

    fn utxo(spk: &ScriptBuf, sats: u64, seed: u8) -> UtxoInfo {
        UtxoInfo {
            outpoint: OutPoint {
                txid: Txid::from_byte_array([seed; 32]),
                vout: 0,
            },
            amount: Amount::from_sat(sats),
            confirmations: 1,
            script_pubkey: spk.clone(),
        }
    }

    #[test]
    fn selects_single_input_with_change() {
        let spk = deposit_spk();
        let candidates = vec![utxo(&spk, 100_000, 1)];
        let recipient = vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: spk.clone(),
        }];
        let (inputs, change) = select_funding(
            &candidates,
            &HashSet::new(),
            &spk,
            &recipient,
            &spk,
            FeeRate::from_sat_per_vb(2).unwrap(),
        )
        .expect("selection succeeds");
        assert_eq!(inputs.len(), 1);
        // Change should be present and well under the 60k surplus (after fee).
        let change = change.expect("change present");
        assert!(change > Amount::ZERO && change < Amount::from_sat(60_000));
    }

    #[test]
    fn skips_utxos_not_at_deposit_address() {
        let spk = deposit_spk();
        let other = ScriptBuf::from_hex("0014000000000000000000000000000000000000beef").unwrap();
        let candidates = vec![utxo(&other, 100_000, 2)];
        let recipient = vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: spk.clone(),
        }];
        let err = select_funding(
            &candidates,
            &HashSet::new(),
            &spk,
            &recipient,
            &spk,
            FeeRate::from_sat_per_vb(2).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, FireblocksError::TxBuild(_)));
    }

    #[test]
    fn insufficient_funds_errors() {
        let spk = deposit_spk();
        let candidates = vec![utxo(&spk, 5_000, 3)];
        let recipient = vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: spk.clone(),
        }];
        assert!(select_funding(
            &candidates,
            &HashSet::new(),
            &spk,
            &recipient,
            &spk,
            FeeRate::from_sat_per_vb(2).unwrap(),
        )
        .is_err());
    }
}
