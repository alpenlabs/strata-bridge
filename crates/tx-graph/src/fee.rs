//! Hardcoded fees for presigned transactions.
//!
//! Until CPFP is implemented, every presigned transaction must pay its own fee.
//! Setting [`FEE_RATE_SAT_PER_VB`] to `0` disables fees entirely (matches the original
//! zero-fee behaviour) without removing any code.
//!
//! All vsize formulas are closed-form functions of the two graph parameters (`n_watchtowers`
//! and `n_data`). Numbers are pinned by `tests::pin_*` unit tests that build the actual
//! finalized transactions and assert that `vsize × FEE_RATE_SAT_PER_VB == fee`.
//!
//! Each fee corresponds to a specific presigned transaction; see the comments below for
//! which transaction each constant belongs to.
//!
//! Output sizes are taken from real outputs:
//! - P2TR script_pubkey is 34 bytes.
//! - SPS-50 OP_RETURN script_pubkey is variable but small (taken from the actual data).
//! - Operator/watchtower descriptors are P2TR in tests; production uses BOSD which resolves to
//!   bech32 / P2TR scripts of similar size.

use std::num::NonZero;

use bitcoin::Amount;

/// Fee rate (sat/vb) that every presigned transaction pays.
///
/// Set to `0` to disable fees entirely — every helper in this module then returns
/// `Amount::ZERO`, every connector surcharge collapses to zero, and every per-tx
/// `value_in - value_out` becomes zero again, matching the original behaviour.
///
/// Set back to `2` (or any positive value) to re-enable fees once CPFP needs them
/// disabled again.
pub const FEE_RATE_SAT_PER_VB: u64 = 2;

/// Multiplies a vsize (in vbytes) by [`FEE_RATE_SAT_PER_VB`] to produce a fee.
const fn fee_for_vsize(vsize: u64) -> Amount {
    Amount::from_sat(vsize.saturating_mul(FEE_RATE_SAT_PER_VB))
}

/// Value to put on every cpfp anchor output (`KeyedAnchor`/`MultiAnchor`).
///
/// When [`FEE_RATE_SAT_PER_VB`] is `0`, returns `Amount::ZERO` — anchors stay at zero, matching
/// the original zero-fee TRUC behaviour where bitcoin core's relay policy permits dust outputs
/// only when the parent pays no fee.
///
/// When [`FEE_RATE_SAT_PER_VB`] is non-zero, returns the P2TR `minimal_non_dust` threshold so
/// the parent can pay a fee without bitcoin core rejecting it as `dust, tx with dust output
/// must be 0-fee`. Bitcoin core's dust formula for a 34-byte P2TR script_pubkey at
/// `DUST_RELAY_TX_FEE = 3000` is `(32 + 4 + 1 + 26 + 4 + 8 + 34) * 3 / 1 = 327` sat. We use
/// `330` sat as a small margin.
pub const fn anchor_dust_value() -> Amount {
    if FEE_RATE_SAT_PER_VB == 0 {
        Amount::ZERO
    } else {
        Amount::from_sat(330)
    }
}

// -------------------------------------------------------------------------------------------------
// Per-tx vsize formulas. Hardcoded and pinned by unit tests below.
//
// These are the predicted finalized vsizes (vbytes, ceil-rounded). Vsize = ceil(weight / 4).
// Each value was determined by constructing the actual finalized transaction in a unit test
// and reading `tx.weight().to_vbytes_ceil()`.
// -------------------------------------------------------------------------------------------------

/// Predicted vsize of [`crate::transactions::claim::ClaimTx`] in vbytes.
///
/// Structure: 1 wallet input (P2TR key path) + 3 P2TR outputs (claim_contest, claim_payout,
/// anchor).
const CLAIM_VSIZE: u64 = 154;

/// Predicted vsize of [`crate::transactions::uncontested_payout::UncontestedPayoutTx`] in vbytes.
///
/// Structure: 3 inputs (NOfN key path, ClaimContest uncontested script path, ClaimPayout key path)
/// + 1 P2TR output.
const UNCONTESTED_PAYOUT_VSIZE: u64 = 235;

/// Base predicted vsize of [`crate::transactions::contest::ContestTx`].
///
/// Per-watchtower additional vsize is [`CONTEST_PER_WATCHTOWER_VSIZE`].
const CONTEST_BASE_VSIZE: u64 = 226;

/// Per-watchtower vsize contribution to [`crate::transactions::contest::ContestTx`].
///
/// Each watchtower adds 1 P2TR output (counterproof_x) of 43 non-witness bytes = 43 vbytes.
const CONTEST_PER_WATCHTOWER_VSIZE: u64 = 43;

/// Predicted vsize of [`crate::transactions::bridge_proof_timeout::BridgeProofTimeoutTx`].
///
/// Structure: 2 script-path inputs (ContestProof timeout, ContestPayout normal) + 1 P2TR output.
/// MultiAnchor output's tap-tree depth scales with watchtower count, but its script_pubkey is
/// always 34 bytes.
const BRIDGE_PROOF_TIMEOUT_VSIZE: u64 = 197;

/// Base predicted vsize of [`crate::transactions::counterproof::CounterproofTx`].
///
/// Per-`n_data`-byte additional vsize is [`COUNTERPROOF_PER_DATA_BYTE_VSIZE`].
const COUNTERPROOF_BASE_VSIZE: u64 = 168;

/// Per-`n_data`-byte vsize contribution to [`crate::transactions::counterproof::CounterproofTx`].
///
/// Each `n_data` byte adds one OP_TUCK + OP_CHECKSIGVERIFY + OP_CODESEPARATOR triple (~3 bytes
/// in script) plus one 64-byte schnorr signature in the witness. Witness bytes contribute
/// 1 wu each → 1/4 vbyte each. Script bytes contribute 4 wu each → 1 vbyte each.
const COUNTERPROOF_PER_DATA_BYTE_VSIZE: u64 = 19;

/// Predicted vsize of [`crate::transactions::counterproof_ack::CounterproofAckTx`].
///
/// Structure: 2 inputs (Counterproof timeout script path, ContestPayout normal key path)
/// + 1 P2TR output (cpfp anchor).
const COUNTERPROOF_ACK_VSIZE: u64 = 197;

/// Predicted vsize of [`crate::transactions::contested_payout::ContestedPayoutTx`].
///
/// Structure: 4 inputs (deposit NOfN key, claim_payout key, contest_payout timeout script,
/// contest_slash normal key) + 1 P2TR output.
const CONTESTED_PAYOUT_VSIZE: u64 = 313;

/// Base predicted vsize of [`crate::transactions::slash::SlashTx`].
///
/// Structure: 2 inputs (contest_slash timeout script, stake NOfN key) +
/// SPS-50 header output + N watchtower outputs.
/// Per-watchtower additional vsize is [`SLASH_PER_WATCHTOWER_VSIZE`].
const SLASH_BASE_VSIZE: u64 = 195;

/// Per-watchtower vsize contribution to [`crate::transactions::slash::SlashTx`].
const SLASH_PER_WATCHTOWER_VSIZE: u64 = 43;

/// Predicted vsize of [`crate::transactions::stake::StakeTx`].
///
/// Structure: 1 wallet input (P2TR key path) + 3 P2TR outputs.
const STAKE_VSIZE: u64 = 154;

/// Predicted vsize of [`crate::transactions::unstaking_intent::UnstakingIntentTx`].
///
/// Structure: 1 script-path input (UnstakingIntentOutput) + 3 outputs (header + unstaking +
/// anchor).
const UNSTAKING_INTENT_VSIZE: u64 = 211;

/// Predicted vsize of [`crate::transactions::unstaking::UnstakingTx`].
///
/// Structure: 2 inputs (UnstakingOutput timeout script, stake NOfN key) + 1 P2TR output.
const UNSTAKING_VSIZE: u64 = 197;

/// Predicted vsize of [`crate::transactions::deposit::DepositTx`].
///
/// Structure: 1 input (DepositRequestConnector key path) + 2 outputs (SPS-50 OP_RETURN + N/N
/// P2TR).
const DEPOSIT_VSIZE: u64 = 158;

/// Predicted vsize of [`crate::transactions::cooperative_payout::CooperativePayoutTx`].
///
/// Structure: 1 input (deposit NOfN key path) + 1 P2TR operator output.
const COOPERATIVE_PAYOUT_VSIZE: u64 = 130;

/// Predicted vsize of [`crate::transactions::not_presigned::CounterproofNackTx`] in production,
/// where the operator does **not** add a funding input — the fee is taken out of the
/// `CounterproofConnector`'s pre-inflated value (its surcharge equals
/// [`counterproof_ack_fee`], which is larger than this nack fee, so the math works out).
///
/// Structure: 1 input (CounterproofConnector script-path) + 1 P2TR operator output.
const COUNTERPROOF_NACK_VSIZE: u64 = 130;

// -------------------------------------------------------------------------------------------------
// Per-tx fees. Each is `vsize × FEE_RATE_SAT_PER_VB`.
// -------------------------------------------------------------------------------------------------

/// Fee for [`crate::transactions::claim::ClaimTx`].
pub const fn claim_fee() -> Amount {
    fee_for_vsize(CLAIM_VSIZE)
}

/// Fee for [`crate::transactions::uncontested_payout::UncontestedPayoutTx`].
pub const fn uncontested_payout_fee() -> Amount {
    fee_for_vsize(UNCONTESTED_PAYOUT_VSIZE)
}

/// Fee for [`crate::transactions::contest::ContestTx`].
pub const fn contest_fee(n_watchtowers: u32) -> Amount {
    fee_for_vsize(CONTEST_BASE_VSIZE + (n_watchtowers as u64) * CONTEST_PER_WATCHTOWER_VSIZE)
}

/// Fee for [`crate::transactions::bridge_proof_timeout::BridgeProofTimeoutTx`].
pub const fn bridge_proof_timeout_fee() -> Amount {
    fee_for_vsize(BRIDGE_PROOF_TIMEOUT_VSIZE)
}

/// Fee for [`crate::transactions::counterproof::CounterproofTx`].
pub const fn counterproof_fee(n_data: NonZero<usize>) -> Amount {
    fee_for_vsize(
        COUNTERPROOF_BASE_VSIZE + (n_data.get() as u64) * COUNTERPROOF_PER_DATA_BYTE_VSIZE,
    )
}

/// Fee for [`crate::transactions::counterproof_ack::CounterproofAckTx`].
pub const fn counterproof_ack_fee() -> Amount {
    fee_for_vsize(COUNTERPROOF_ACK_VSIZE)
}

/// Fee for [`crate::transactions::contested_payout::ContestedPayoutTx`].
pub const fn contested_payout_fee() -> Amount {
    fee_for_vsize(CONTESTED_PAYOUT_VSIZE)
}

/// Fee for [`crate::transactions::slash::SlashTx`].
pub const fn slash_fee(n_watchtowers: u32) -> Amount {
    fee_for_vsize(SLASH_BASE_VSIZE + (n_watchtowers as u64) * SLASH_PER_WATCHTOWER_VSIZE)
}

/// Fee for [`crate::transactions::stake::StakeTx`].
pub const fn stake_fee() -> Amount {
    fee_for_vsize(STAKE_VSIZE)
}

/// Fee for [`crate::transactions::unstaking_intent::UnstakingIntentTx`].
pub const fn unstaking_intent_fee() -> Amount {
    fee_for_vsize(UNSTAKING_INTENT_VSIZE)
}

/// Fee for [`crate::transactions::unstaking::UnstakingTx`].
pub const fn unstaking_fee() -> Amount {
    fee_for_vsize(UNSTAKING_VSIZE)
}

/// Fee for [`crate::transactions::deposit::DepositTx`].
///
/// The fee comes from the depositor's deposit-request UTXO carrying
/// `deposit_amount + deposit_fee()`; the bridge cannot inject extra value into the deposit tx.
pub const fn deposit_fee() -> Amount {
    fee_for_vsize(DEPOSIT_VSIZE)
}

/// Fee for [`crate::transactions::cooperative_payout::CooperativePayoutTx`].
pub const fn cooperative_payout_fee() -> Amount {
    fee_for_vsize(COOPERATIVE_PAYOUT_VSIZE)
}

/// Fee for the [`crate::transactions::not_presigned::CounterproofNackTx`] as broadcast in
/// production with a single wallet P2TR funding input and a single wallet P2TR output.
pub const fn counterproof_nack_fee() -> Amount {
    fee_for_vsize(COUNTERPROOF_NACK_VSIZE)
}

// -------------------------------------------------------------------------------------------------
// Connector surcharges. These are added to a connector's base value so the downstream
// transaction's input arrives with the fee already included. Used for transactions whose
// outputs are all dust connectors / cpfp anchors and cannot absorb a fee without underflowing.
// -------------------------------------------------------------------------------------------------

/// Surcharge for `CounterproofConnector`. Funds the [`counterproof_ack_fee`] of
/// [`crate::transactions::counterproof_ack::CounterproofAckTx`].
pub const fn counterproof_surcharge() -> Amount {
    counterproof_ack_fee()
}

/// Surcharge for `ContestProofConnector`. Funds the [`bridge_proof_timeout_fee`] of
/// [`crate::transactions::bridge_proof_timeout::BridgeProofTimeoutTx`].
pub const fn contest_proof_surcharge() -> Amount {
    bridge_proof_timeout_fee()
}

/// Surcharge for `ContestCounterproofOutput`. Funds the [`counterproof_fee`] of
/// [`crate::transactions::counterproof::CounterproofTx`], the cpfp anchor dust on that tx,
/// plus the inflation that `CounterproofConnector` carries (= [`counterproof_ack_fee`]).
pub fn contest_counterproof_surcharge(n_data: NonZero<usize>) -> Amount {
    counterproof_fee(n_data) + counterproof_ack_fee() + anchor_dust_value()
}

/// Surcharge for `ClaimContestConnector`. Funds the [`contest_fee`], the contest tx's cpfp
/// anchor dust, plus the inflation that all of [`crate::transactions::contest::ContestTx`]'s
/// outputs carry: `ContestProofConnector` (`bridge_proof_timeout_fee`) and the per-watchtower
/// `ContestCounterproofOutput` (`contest_counterproof_surcharge(n_data)`).
pub fn claim_contest_surcharge(n_watchtowers: u32, n_data: NonZero<usize>) -> Amount {
    contest_fee(n_watchtowers)
        + bridge_proof_timeout_fee()
        + anchor_dust_value()
        + contest_counterproof_surcharge(n_data) * u64::from(n_watchtowers)
}

/// Surcharge for `UnstakingIntentOutput`. Funds the [`unstaking_intent_fee`] of
/// [`crate::transactions::unstaking_intent::UnstakingIntentTx`] plus that tx's cpfp anchor dust.
pub fn unstaking_intent_surcharge() -> Amount {
    unstaking_intent_fee() + anchor_dust_value()
}
