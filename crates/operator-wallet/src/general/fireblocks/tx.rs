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
    Amount, EcdsaSighashType, FeeRate, OutPoint, Script, ScriptBuf, Sequence, Transaction, TxIn,
    TxOut, Witness,
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

/// Builds [`FundingInput`]s for an explicit input set, looking each outpoint up in `candidates`,
/// and computes the change amount (dropping change below dust into the fee).
///
/// `candidates` is the synced UTXO snapshot, which is already filtered to the single deposit
/// address (see `sync` in `fireblocks.rs`), so every found input is implicitly P2WPKH at that
/// address; an outpoint not at the deposit address simply isn't in `candidates` and errors below.
///
/// Errors if any requested outpoint is absent from `candidates`, or if the chosen inputs can't
/// cover `recipient_outputs` plus the fee at `fee_rate`.
pub(super) fn funding_from_explicit(
    candidates: &[UtxoInfo],
    explicit_inputs: &[OutPoint],
    recipient_outputs: &[TxOut],
    change_spk: &Script,
    fee_rate: FeeRate,
) -> Result<(Vec<FundingInput>, Option<Amount>), FireblocksError> {
    let mut funding = Vec::with_capacity(explicit_inputs.len());
    let mut total_in = Amount::ZERO;
    for op in explicit_inputs {
        let u = candidates
            .iter()
            .find(|u| u.outpoint == *op)
            .ok_or_else(|| {
                FireblocksError::TxBuild(format!("explicit input {op} not in wallet UTXO set"))
            })?;
        funding.push(FundingInput {
            outpoint: *op,
            prevout: TxOut {
                value: u.amount,
                script_pubkey: u.script_pubkey.clone(),
            },
        });
        total_in = total_in
            .checked_add(u.amount)
            .ok_or_else(|| FireblocksError::TxBuild("input total overflows".into()))?;
    }

    let recipient_total = recipient_outputs
        .iter()
        .try_fold(Amount::ZERO, |acc, o| acc.checked_add(o.value))
        .ok_or_else(|| FireblocksError::TxBuild("recipient output total overflows".into()))?;
    let recipient_lens: Vec<usize> = recipient_outputs
        .iter()
        .map(|o| o.script_pubkey.len())
        .collect();
    let fee_with_change = fee_for(
        funding.len(),
        &recipient_lens,
        Some(change_spk.len()),
        fee_rate,
    )?;
    let fee_no_change = fee_for(funding.len(), &recipient_lens, None, fee_rate)?;

    let need_no_change = recipient_total
        .checked_add(fee_no_change)
        .ok_or_else(|| FireblocksError::TxBuild("recipient total + fee overflows".into()))?;
    if total_in < need_no_change {
        return Err(FireblocksError::TxBuild(format!(
            "explicit inputs total {total_in} cannot cover {recipient_total} + fee"
        )));
    }
    let change = total_in
        .checked_sub(recipient_total)
        .and_then(|r| r.checked_sub(fee_with_change))
        .filter(|rem| *rem >= change_spk.minimal_non_dust());
    Ok((funding, change))
}

/// Selects P2WPKH funding inputs (from `candidates` at `deposit_spk`, largest first) for a CPFP
/// child so the `[parent, child]` package reaches `target_pkg_fee_rate`. The child spends the
/// combined input (value `combined_value`) plus the selected inputs and pays a single change
/// output; its fee is the package shortfall after the parent's own fee, floored at 1 sat/vB of
/// the child's own vbytes (a sub-1-sat/vB v3 child is nonstandard under BIP-431/TRUC and
/// `submitpackage` would reject the whole package).
///
/// `combined_is_p2wpkh` distinguishes the two combined-input shapes for the fee estimate: the
/// operator's own P2WPKH payout (every input is P2WPKH) vs. a foreign keyed-Taproot anchor (one
/// P2TR input + the P2WPKH funding inputs).
///
/// Returns the funding inputs (possibly empty when the combined input alone covers the fee) and
/// the child's output (change) value.
#[expect(
    clippy::too_many_arguments,
    reason = "cohesive CPFP fee-selection inputs; bundling into a struct would only add indirection"
)]
pub(super) fn select_cpfp_funding(
    candidates: &[UtxoInfo],
    exclude: &HashSet<OutPoint>,
    deposit_spk: &Script,
    combined_value: Amount,
    combined_is_p2wpkh: bool,
    parent_vsize: u64,
    parent_fee: Amount,
    target_pkg_fee_rate: FeeRate,
    change_spk: &Script,
) -> Result<(Vec<FundingInput>, Amount), FireblocksError> {
    let dust = change_spk.minimal_non_dust();
    let change_len = change_spk.len();

    // Child output (change) for `n_funding` P2WPKH funding inputs contributing `funding_total`;
    // `None` if it can't clear dust or the arithmetic overflows.
    let try_fit = |n_funding: usize, funding_total: Amount| -> Option<Amount> {
        let n_p2wpkh = n_funding + usize::from(combined_is_p2wpkh);
        let child_vsize = cpfp_child_vsize(n_p2wpkh, !combined_is_p2wpkh, change_len);
        let package_fee = target_pkg_fee_rate.fee_vb(parent_vsize.saturating_add(child_vsize))?;
        // The child makes up the package shortfall after the parent's fee, but must pay at least
        // 1 sat/vB on its own vbytes. If the parent already overpays the target, floor the child
        // to its own size. Same ≥1-sat/vB child floor as the native backend (`native.rs`
        // build_cpfp_child), computed here on the actual predicted child vsize.
        let shortfall = package_fee.checked_sub(parent_fee).unwrap_or(Amount::ZERO);
        let child_fee = shortfall.max(Amount::from_sat(child_vsize));
        combined_value
            .checked_add(funding_total)
            .and_then(|t| t.checked_sub(child_fee))
            .filter(|out| *out >= dust)
    };

    // The combined input alone may already cover the package fee — common when CPFP-ing a payout
    // whose value dwarfs the bump fee.
    if let Some(child_output) = try_fit(0, Amount::ZERO) {
        return Ok((Vec::new(), child_output));
    }

    let mut eligible: Vec<&UtxoInfo> = candidates
        .iter()
        .filter(|u| u.script_pubkey == *deposit_spk && !exclude.contains(&u.outpoint))
        .collect();
    eligible.sort_by_key(|u| std::cmp::Reverse(u.amount));

    let mut selected: Vec<FundingInput> = Vec::new();
    let mut funding_total = Amount::ZERO;
    for u in eligible {
        selected.push(FundingInput {
            outpoint: u.outpoint,
            prevout: TxOut {
                value: u.amount,
                script_pubkey: u.script_pubkey.clone(),
            },
        });
        funding_total = funding_total
            .checked_add(u.amount)
            .ok_or_else(|| FireblocksError::TxBuild("input total overflows".into()))?;
        if let Some(child_output) = try_fit(selected.len(), funding_total) {
            return Ok((selected, child_output));
        }
    }
    Err(FireblocksError::TxBuild(
        "insufficient funds to build CPFP child at target package fee rate".into(),
    ))
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

/// Computes the BIP-143 sighash (SIGHASH_ALL) for the P2WPKH input at `input_index` of `tx`.
/// `prevouts[i]` must be the output spent by `tx.input[i]`.
pub(super) fn p2wpkh_sighash(
    tx: &Transaction,
    input_index: usize,
    prevouts: &[TxOut],
) -> Result<[u8; 32], FireblocksError> {
    let prevout = prevouts
        .get(input_index)
        .ok_or_else(|| FireblocksError::TxBuild(format!("no prevout for input {input_index}")))?;
    let mut cache = bdk_wallet::bitcoin::sighash::SighashCache::new(tx);
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
    use bdk_wallet::bitcoin::{hashes::Hash, key::Secp256k1, Address, Network, Txid};

    use super::*;

    fn deposit_spk() -> ScriptBuf {
        let kp =
            bdk_wallet::bitcoin::key::Keypair::from_seckey_slice(&Secp256k1::new(), &[7u8; 32])
                .unwrap();
        // A P2WPKH address derived from the compressed key.
        let pk = bdk_wallet::bitcoin::PublicKey::new(kp.public_key());
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

    #[test]
    fn selects_multiple_inputs_when_one_is_short() {
        let spk = deposit_spk();
        let candidates = vec![utxo(&spk, 30_000, 1), utxo(&spk, 30_000, 2)];
        let recipient = vec![TxOut {
            value: Amount::from_sat(45_000),
            script_pubkey: spk.clone(),
        }];
        let (inputs, _change) = select_funding(
            &candidates,
            &HashSet::new(),
            &spk,
            &recipient,
            &spk,
            FeeRate::from_sat_per_vb(2).unwrap(),
        )
        .expect("two inputs cover the recipient");
        assert_eq!(inputs.len(), 2);
    }

    #[test]
    fn absorbs_sub_dust_remainder_into_fee() {
        let spk = deposit_spk();
        // Pick an input value that leaves only a few sats over recipient+fee — below the change
        // dust threshold, so the remainder is absorbed into the fee (no change output).
        let recipient_value = 40_000u64;
        let fee = fee_for(1, &[spk.len()], None, FeeRate::from_sat_per_vb(2).unwrap())
            .unwrap()
            .to_sat();
        let candidates = vec![utxo(&spk, recipient_value + fee + 10, 4)];
        let recipient = vec![TxOut {
            value: Amount::from_sat(recipient_value),
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
        .expect("covers recipient + fee");
        assert_eq!(inputs.len(), 1);
        assert!(
            change.is_none(),
            "sub-dust remainder must be absorbed into the fee"
        );
    }

    #[test]
    fn keeps_change_exactly_at_dust_threshold() {
        let spk = deposit_spk();
        let rate = FeeRate::from_sat_per_vb(2).unwrap();
        let recipient_value = 40_000u64;
        let dust = spk.minimal_non_dust().to_sat();
        // Fee for the single-input, one-recipient-plus-change layout this selection produces.
        let fee = fee_for(1, &[spk.len()], Some(spk.len()), rate)
            .unwrap()
            .to_sat();
        // Fund exactly recipient + fee + dust, so the remainder lands precisely on the inclusive
        // `>= dust` boundary and must be kept as change.
        let candidates = vec![utxo(&spk, recipient_value + fee + dust, 5)];
        let recipient = vec![TxOut {
            value: Amount::from_sat(recipient_value),
            script_pubkey: spk.clone(),
        }];
        let (inputs, change) =
            select_funding(&candidates, &HashSet::new(), &spk, &recipient, &spk, rate)
                .expect("covers recipient + fee + dust change");
        assert_eq!(inputs.len(), 1);
        assert_eq!(
            change.expect("change at the dust boundary is kept"),
            Amount::from_sat(dust)
        );
    }

    #[test]
    fn excludes_listed_outpoints() {
        let spk = deposit_spk();
        let u = utxo(&spk, 100_000, 7);
        let mut exclude = HashSet::new();
        exclude.insert(u.outpoint);
        let recipient = vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: spk.clone(),
        }];
        assert!(select_funding(
            &[u],
            &exclude,
            &spk,
            &recipient,
            &spk,
            FeeRate::from_sat_per_vb(2).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn explicit_funding_with_change() {
        let spk = deposit_spk();
        let u = utxo(&spk, 100_000, 1);
        let recipient = vec![TxOut {
            value: Amount::from_sat(40_000),
            script_pubkey: spk.clone(),
        }];
        let (inputs, change) = funding_from_explicit(
            std::slice::from_ref(&u),
            &[u.outpoint],
            &recipient,
            &spk,
            FeeRate::from_sat_per_vb(2).unwrap(),
        )
        .expect("explicit input covers recipient");
        assert_eq!(inputs.len(), 1);
        assert_eq!(inputs[0].outpoint, u.outpoint);
        assert!(change.expect("change present") > Amount::ZERO);
    }

    #[test]
    fn explicit_funding_change_at_and_below_dust_boundary() {
        let spk = deposit_spk();
        let rate = FeeRate::from_sat_per_vb(2).unwrap();
        let recipient_value = 40_000u64;
        let dust = spk.minimal_non_dust().to_sat();
        let fee = fee_for(1, &[spk.len()], Some(spk.len()), rate)
            .unwrap()
            .to_sat();
        let recipient = vec![TxOut {
            value: Amount::from_sat(recipient_value),
            script_pubkey: spk.clone(),
        }];

        // Exactly at the inclusive `>= dust` boundary: change is kept.
        let at = utxo(&spk, recipient_value + fee + dust, 1);
        let (_, change) = funding_from_explicit(
            std::slice::from_ref(&at),
            &[at.outpoint],
            &recipient,
            &spk,
            rate,
        )
        .expect("covers recipient + fee + dust");
        assert_eq!(
            change.expect("change at dust boundary kept"),
            Amount::from_sat(dust)
        );

        // One sat below dust: remainder is absorbed into the fee (no change output).
        let below = utxo(&spk, recipient_value + fee + dust - 1, 2);
        let (_, change) = funding_from_explicit(
            std::slice::from_ref(&below),
            &[below.outpoint],
            &recipient,
            &spk,
            rate,
        )
        .expect("covers recipient + fee");
        assert!(
            change.is_none(),
            "sub-dust remainder is absorbed into the fee"
        );
    }

    #[test]
    fn explicit_funding_missing_input_errors() {
        let spk = deposit_spk();
        let present = utxo(&spk, 100_000, 1);
        let missing = utxo(&spk, 100_000, 2);
        let recipient = vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: spk.clone(),
        }];
        let err = funding_from_explicit(
            &[present],
            &[missing.outpoint],
            &recipient,
            &spk,
            FeeRate::from_sat_per_vb(2).unwrap(),
        )
        .unwrap_err();
        assert!(matches!(err, FireblocksError::TxBuild(_)));
    }

    #[test]
    fn explicit_funding_insufficient_errors() {
        let spk = deposit_spk();
        let u = utxo(&spk, 5_000, 1);
        let recipient = vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: spk.clone(),
        }];
        assert!(funding_from_explicit(
            std::slice::from_ref(&u),
            &[u.outpoint],
            &recipient,
            &spk,
            FeeRate::from_sat_per_vb(2).unwrap(),
        )
        .is_err());
    }

    #[test]
    fn cpfp_combined_input_alone_covers_fee() {
        let spk = deposit_spk();
        // A large own-payout combined input dwarfs the bump fee, so no funding is pulled.
        let (funding, child_output) = select_cpfp_funding(
            &[],
            &HashSet::new(),
            &spk,
            Amount::from_sat(100_000), // combined value
            true,                      // combined is our P2WPKH payout
            150,                       // parent vsize
            Amount::ZERO,              // parent fee
            FeeRate::from_sat_per_vb(2).unwrap(),
            &spk,
        )
        .expect("combined input alone covers the fee");
        assert!(funding.is_empty());
        assert!(child_output >= spk.minimal_non_dust());
    }

    #[test]
    fn cpfp_pulls_funding_when_combined_is_short() {
        let spk = deposit_spk();
        let candidates = vec![utxo(&spk, 50_000, 9)];
        let (funding, child_output) = select_cpfp_funding(
            &candidates,
            &HashSet::new(),
            &spk,
            Amount::from_sat(400), // tiny combined input
            true,
            150,
            Amount::ZERO,
            FeeRate::from_sat_per_vb(2).unwrap(),
            &spk,
        )
        .expect("a funding input covers the shortfall");
        assert_eq!(funding.len(), 1);
        assert!(child_output >= spk.minimal_non_dust());
    }

    #[test]
    fn cpfp_foreign_taproot_anchor_pulls_funding() {
        let spk = deposit_spk();
        let candidates = vec![utxo(&spk, 50_000, 9)];
        let (funding, child_output) = select_cpfp_funding(
            &candidates,
            &HashSet::new(),
            &spk,
            Amount::from_sat(330), // foreign keyed-Taproot anchor value
            false,                 // not our P2WPKH; the anchor is a P2TR input
            150,
            Amount::ZERO,
            FeeRate::from_sat_per_vb(2).unwrap(),
            &spk,
        )
        .expect("funding covers the package fee");
        assert_eq!(funding.len(), 1);
        assert!(child_output >= spk.minimal_non_dust());
    }

    #[test]
    fn cpfp_insufficient_funds_errors() {
        let spk = deposit_spk();
        let err = select_cpfp_funding(
            &[],
            &HashSet::new(),
            &spk,
            Amount::from_sat(330),
            false,
            150,
            Amount::ZERO,
            FeeRate::from_sat_per_vb(5).unwrap(),
            &spk,
        )
        .unwrap_err();
        assert!(matches!(err, FireblocksError::TxBuild(_)));
    }
}
